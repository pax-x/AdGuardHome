package dnsforward

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/bluele/gcache"
	"github.com/miekg/dns"
)

type hourTop struct {
	domains gcache.Cache
	blocked gcache.Cache
	clients gcache.Cache

	mutex sync.RWMutex
}

func (h *hourTop) init() {
	h.domains = gcache.New(queryLogTopSize).LRU().Build()
	h.blocked = gcache.New(queryLogTopSize).LRU().Build()
	h.clients = gcache.New(queryLogTopSize).LRU().Build()
}

type dayTop struct {
	limit     int
	hours     []*hourTop
	hoursLock sync.RWMutex // writelock this lock ONLY WHEN rotating or intializing hours!
}

func (d *dayTop) init(limit int) {
	a := []*hourTop{}
	for i := 0; i < limit; i++ {
		hour := hourTop{}
		hour.init()
		a = append(a, &hour)
	}

	d.hoursLock.Lock()
	if len(d.hours) == 0 {
		d.hours = a
	} else if limit > d.limit {
		d.hours = append(d.hours, a[:limit-d.limit]...)
	} else if limit < d.limit {
		d.hours = d.hours[:d.limit-limit]
	}
	d.limit = limit
	d.hoursLock.Unlock()
}

func (d *dayTop) rotateHourlyTop() {
	log.Printf("Rotating hourly top")
	hour := &hourTop{}
	hour.init()
	d.hoursLock.Lock()
	d.hours = append([]*hourTop{hour}, d.hours...)
	d.hours = d.hours[:d.limit]
	d.hoursLock.Unlock()
}

func (d *dayTop) periodicHourlyTopRotate() {
	t := time.Hour
	for range time.Tick(t) {
		d.rotateHourlyTop()
	}
}

func (h *hourTop) incrementValue(key string, cache gcache.Cache) error {
	h.Lock()
	defer h.Unlock()
	ivalue, err := cache.Get(key)
	if err == gcache.KeyNotFoundError {
		// we just set it and we're done
		err = cache.Set(key, 1)
		if err != nil {
			log.Printf("Failed to set hourly top value: %s", err)
			return err
		}
		return nil
	}

	if err != nil {
		log.Printf("gcache encountered an error during get: %s", err)
		return err
	}

	cachedValue, ok := ivalue.(int)
	if !ok {
		err = fmt.Errorf("SHOULD NOT HAPPEN: gcache has non-int as value: %v", ivalue)
		log.Println(err)
		return err
	}

	err = cache.Set(key, cachedValue+1)
	if err != nil {
		log.Printf("Failed to set hourly top value: %s", err)
		return err
	}
	return nil
}

func (h *hourTop) incrementDomains(key string) error {
	return h.incrementValue(key, h.domains)
}

func (h *hourTop) incrementBlocked(key string) error {
	return h.incrementValue(key, h.blocked)
}

func (h *hourTop) incrementClients(key string) error {
	return h.incrementValue(key, h.clients)
}

// if does not exist -- return 0
func (h *hourTop) lockedGetValue(key string, cache gcache.Cache) (int, error) {
	ivalue, err := cache.Get(key)
	if err == gcache.KeyNotFoundError {
		return 0, nil
	}

	if err != nil {
		log.Printf("gcache encountered an error during get: %s", err)
		return 0, err
	}

	value, ok := ivalue.(int)
	if !ok {
		err := fmt.Errorf("SHOULD NOT HAPPEN: gcache has non-int as value: %v", ivalue)
		log.Println(err)
		return 0, err
	}

	return value, nil
}

func (h *hourTop) lockedGetDomains(key string) (int, error) {
	return h.lockedGetValue(key, h.domains)
}

func (h *hourTop) lockedGetBlocked(key string) (int, error) {
	return h.lockedGetValue(key, h.blocked)
}

func (h *hourTop) lockedGetClients(key string) (int, error) {
	return h.lockedGetValue(key, h.clients)
}

func (d *dayTop) addEntry(entry *logEntry, q *dns.Msg, now time.Time) error {
	// figure out which hour bucket it belongs to
	hour := int(now.Sub(entry.Time).Hours())
	if hour >= d.limit {
		log.Printf("t %v is very old, ignoring", entry.Time)
		return nil
	}

	// if a DNS query doesn't have questions, do nothing
	if len(q.Question) == 0 {
		return nil
	}

	hostname := strings.ToLower(strings.TrimSuffix(q.Question[0].Name, "."))

	// if question hostname is empty, do nothing
	if hostname == "" {
		return nil
	}

	// get value, if not set, crate one
	d.hoursLock.RLock()
	defer d.hoursLock.RUnlock()
	err := d.hours[hour].incrementDomains(hostname)
	if err != nil {
		log.Printf("Failed to increment value: %s", err)
		return err
	}

	if entry.Result.IsFiltered {
		err := d.hours[hour].incrementBlocked(hostname)
		if err != nil {
			log.Printf("Failed to increment value: %s", err)
			return err
		}
	}

	if len(entry.IP) > 0 {
		err := d.hours[hour].incrementClients(entry.IP)
		if err != nil {
			log.Printf("Failed to increment value: %s", err)
			return err
		}
	}

	return nil
}

func (l *queryLog) fillStatsFromQueryLog(s *stats) error {
	now := time.Now()
	validFrom := now.Unix() - int64(l.timeLimit*60*60)

	r := l.OpenReader()
	if r == nil {
		return nil
	}

	r.BeginRead(0, 0)

	for {
		entry := r.Next()
		if entry == nil {
			break
		}

		if entry.Time.Unix() < validFrom {
			continue
		}

		if len(entry.Question) == 0 {
			log.Debug("entry question is absent, skipping")
			continue
		}

		if entry.Time.After(now) {
			log.Debug("t %v vs %v is in the future, ignoring", entry.Time, now)
			continue
		}

		q := new(dns.Msg)
		if err := q.Unpack(entry.Question); err != nil {
			log.Debug("failed to unpack dns message question: %s", err)
			continue
		}

		if len(q.Question) != 1 {
			log.Debug("malformed dns message, has no questions, skipping")
			continue
		}

		err := l.runningTop.addEntry(entry, q, now)
		if err != nil {
			log.Debug("Failed to add entry to running top: %s", err)
			continue
		}

		s.incrementCounters(entry)
	}

	r.Close()
	return nil
}

// StatsTop represents top stat charts
type StatsTop struct {
	Domains map[string]int // Domains - top requested domains
	Blocked map[string]int // Blocked - top blocked domains
	Clients map[string]int // Clients - top DNS clients
}

// getStatsTop returns the current top stats
// hourOffset: Get data from [NOW-hourOffset..NOW]
func (d *dayTop) getStatsTop(hourOffset int) *StatsTop {
	s := &StatsTop{
		Domains: map[string]int{},
		Blocked: map[string]int{},
		Clients: map[string]int{},
	}

	do := func(keys []interface{}, getter func(key string) (int, error), result map[string]int) {
		for _, ikey := range keys {
			key, ok := ikey.(string)
			if !ok {
				continue
			}
			value, err := getter(key)
			if err != nil {
				log.Printf("Failed to get top domains value for %v: %s", key, err)
				return
			}
			result[key] += value
		}
	}

	d.hoursLock.RLock()
	if hourOffset > len(d.hours) {
		hourOffset = len(d.hours)
	}
	for hour := 0; hour < hourOffset; hour++ {
		d.hours[hour].RLock()
		do(d.hours[hour].domains.Keys(), d.hours[hour].lockedGetDomains, s.Domains)
		do(d.hours[hour].blocked.Keys(), d.hours[hour].lockedGetBlocked, s.Blocked)
		do(d.hours[hour].clients.Keys(), d.hours[hour].lockedGetClients, s.Clients)
		d.hours[hour].RUnlock()
	}
	d.hoursLock.RUnlock()

	return s
}

func (h *hourTop) Lock()    { tracelock(); h.mutex.Lock() }
func (h *hourTop) RLock()   { tracelock(); h.mutex.RLock() }
func (h *hourTop) RUnlock() { tracelock(); h.mutex.RUnlock() }
func (h *hourTop) Unlock()  { tracelock(); h.mutex.Unlock() }

func tracelock() {
	if false { // not commented out to make code checked during compilation
		pc := make([]uintptr, 10) // at least 1 entry needed
		runtime.Callers(2, pc)
		f := path.Base(runtime.FuncForPC(pc[1]).Name())
		lockf := path.Base(runtime.FuncForPC(pc[0]).Name())
		fmt.Fprintf(os.Stderr, "%s(): %s\n", f, lockf)
	}
}
