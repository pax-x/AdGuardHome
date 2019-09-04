package querylog

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/go-test/deep"
	"github.com/miekg/dns"
)

var (
	fileWriteLock sync.Mutex
)

const enableGzip = false

// flushLogBuffer flushes the current buffer to file and resets the current buffer
func (l *queryLog) flushLogBuffer(fullFlush bool) error {
	l.fileFlushLock.Lock()
	defer l.fileFlushLock.Unlock()

	// flush remainder to file
	l.logBufferLock.Lock()
	needFlush := len(l.logBuffer) >= logBufferCap
	if !needFlush && !fullFlush {
		l.logBufferLock.Unlock()
		return nil
	}
	flushBuffer := l.logBuffer
	l.logBuffer = nil
	l.flushPending = false
	l.logBufferLock.Unlock()
	err := l.flushToFile(flushBuffer)
	if err != nil {
		log.Error("Saving querylog to file failed: %s", err)
		return err
	}
	return nil
}

// flushToFile saves the specified log entries to the query log file
func (l *queryLog) flushToFile(buffer []*logEntry) error {
	if len(buffer) == 0 {
		log.Debug("querylog: there's nothing to write to a file")
		return nil
	}
	start := time.Now()

	var b bytes.Buffer
	e := json.NewEncoder(&b)
	for _, entry := range buffer {
		err := e.Encode(entry)
		if err != nil {
			log.Error("Failed to marshal entry: %s", err)
			return err
		}
	}

	elapsed := time.Since(start)
	log.Debug("%d elements serialized via json in %v: %d kB, %v/entry, %v/entry", len(buffer), elapsed, b.Len()/1024, float64(b.Len())/float64(len(buffer)), elapsed/time.Duration(len(buffer)))

	err := checkBuffer(buffer, b)
	if err != nil {
		log.Error("failed to check buffer: %s", err)
		return err
	}

	var zb bytes.Buffer
	filename := l.logFile

	// gzip enabled?
	if enableGzip {
		filename += ".gz"

		zw := gzip.NewWriter(&zb)
		zw.Name = l.logFile
		zw.ModTime = time.Now()

		_, err = zw.Write(b.Bytes())
		if err != nil {
			log.Error("Couldn't compress to gzip: %s", err)
			zw.Close()
			return err
		}

		if err = zw.Close(); err != nil {
			log.Error("Couldn't close gzip writer: %s", err)
			return err
		}
	} else {
		zb = b
	}

	fileWriteLock.Lock()
	defer fileWriteLock.Unlock()
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Error("failed to create file \"%s\": %s", filename, err)
		return err
	}
	defer f.Close()

	n, err := f.Write(zb.Bytes())
	if err != nil {
		log.Error("Couldn't write to file: %s", err)
		return err
	}

	log.Debug("ok \"%s\": %v bytes written", filename, n)

	return nil
}

func checkBuffer(buffer []*logEntry, b bytes.Buffer) error {
	l := len(buffer)
	d := json.NewDecoder(&b)

	i := 0
	for d.More() {
		entry := &logEntry{}
		err := d.Decode(entry)
		if err != nil {
			log.Error("Failed to decode: %s", err)
			return err
		}
		if diff := deep.Equal(entry, buffer[i]); diff != nil {
			log.Error("decoded buffer differs: %s", diff)
			return fmt.Errorf("decoded buffer differs: %s", diff)
		}
		i++
	}
	if i != l {
		err := fmt.Errorf("check fail: %d vs %d entries", l, i)
		log.Error("%v", err)
		return err
	}
	log.Debug("check ok: %d entries", i)

	return nil
}

func (l *queryLog) rotateQueryLog() error {
	from := l.logFile
	to := l.logFile + ".1"

	if enableGzip {
		from = l.logFile + ".gz"
		to = l.logFile + ".gz.1"
	}

	if _, err := os.Stat(from); os.IsNotExist(err) {
		// do nothing, file doesn't exist
		return nil
	}

	err := os.Rename(from, to)
	if err != nil {
		log.Error("Failed to rename querylog: %s", err)
		return err
	}

	log.Debug("Rotated from %s to %s successfully", from, to)

	return nil
}

func (l *queryLog) periodicQueryLogRotate() {
	for range time.Tick(l.conf.Interval) {
		err := l.rotateQueryLog()
		if err != nil {
			log.Error("Failed to rotate querylog: %s", err)
			// do nothing, continue rotating
		}
	}
}

func (l *queryLog) genericLoader(onEntry func(entry *logEntry) error, needMore func() bool, timeWindow time.Duration) error {
	now := time.Now()
	// read from querylog files, try newest file first
	var files []string

	if enableGzip {
		files = []string{
			l.logFile + ".gz",
			l.logFile + ".gz.1",
		}
	} else {
		files = []string{
			l.logFile,
			l.logFile + ".1",
		}
	}

	// read from all files
	for _, file := range files {
		if !needMore() {
			break
		}
		if _, err := os.Stat(file); os.IsNotExist(err) {
			// do nothing, file doesn't exist
			continue
		}

		f, err := os.Open(file)
		if err != nil {
			log.Error("Failed to open file \"%s\": %s", file, err)
			// try next file
			continue
		}
		defer f.Close()

		var d *json.Decoder

		if enableGzip {
			zr, err := gzip.NewReader(f)
			if err != nil {
				log.Error("Failed to create gzip reader: %s", err)
				continue
			}
			defer zr.Close()
			d = json.NewDecoder(zr)
		} else {
			d = json.NewDecoder(f)
		}

		i := 0
		over := 0
		max := 10000 * time.Second
		var sum time.Duration
		// entries on file are in oldest->newest order
		// we want maxLen newest
		for d.More() {
			if !needMore() {
				break
			}
			var entry logEntry
			err := d.Decode(&entry)
			if err != nil {
				log.Error("Failed to decode: %s", err)
				// next entry can be fine, try more
				continue
			}

			if now.Sub(entry.Time) > timeWindow {
				continue
			}

			if entry.Elapsed > max {
				over++
			} else {
				sum += entry.Elapsed
			}

			i++
			err = onEntry(&entry)
			if err != nil {
				return err
			}
		}
		elapsed := time.Since(now)
		var perunit time.Duration
		var avg time.Duration
		if i > 0 {
			perunit = elapsed / time.Duration(i)
			avg = sum / time.Duration(i)
		}
		log.Debug("file \"%s\": read %d entries in %v, %v/entry, %v over %v, %v avg", file, i, elapsed, perunit, over, max, avg)
	}
	return nil
}

func (l *queryLog) fillFromFile() {
	now := time.Now()
	onEntry := func(entry *logEntry) error {
		if len(entry.Question) == 0 {
			log.Printf("entry question is absent, skipping")
			return nil
		}

		if entry.Time.After(now) {
			log.Printf("t %v vs %v is in the future, ignoring", entry.Time, now)
			return nil
		}

		q := new(dns.Msg)
		if err := q.Unpack(entry.Question); err != nil {
			log.Printf("failed to unpack dns message question: %s", err)
			return err
		}

		if len(q.Question) != 1 {
			log.Printf("malformed dns message, has no questions, skipping")
			return nil
		}

		l.queryLogLock.Lock()
		l.queryLogCache = append(l.queryLogCache, entry)
		if len(l.queryLogCache) > queryLogSize {
			toremove := len(l.queryLogCache) - queryLogSize
			l.queryLogCache = l.queryLogCache[toremove:]
		}
		l.queryLogLock.Unlock()
		return nil
	}

	needMore := func() bool { return true }
	err := l.genericLoader(onEntry, needMore, l.conf.Interval)
	if err != nil {
		log.Printf("Failed to load entries from querylog: %s", err)
		return
	}
}
