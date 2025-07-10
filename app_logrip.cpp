
//--------------------------------------------------------------------------------
// 
// LogRip
// 
// Copyright 2019-205 (c) Quanta Sciences, Rama Hoetzlein, ramakarl.com
// * Derivative works may append the above copyright notice but should not remove or modify earlier notices.
//
// MIT License
//

#include "main.h"
#include "timex.h"
#include "vec.h"
#include "string_helper.h"
#include "imagex.h"
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
  #include <conio.h>
#endif

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
using namespace httplib;

#define L_STATUS		0
#define L_COUNTRY		1
#define L_REGION		2
#define L_CITY			3
#define L_ZIP				4
#define L_LAT				5
#define L_LONG			6
#define L_ISP				7
#define L_ORG				8
#define L_ASNAME		9

#define I_ORIG			0
#define I_BLOCKED		1
#define I_FILTERED	2
#define I_NUM				3

// log entry
struct LogInfo {
	TimeX					date;
	std::string		page;
	uint32_t			ip;
	int						block;
};

// subnets
#define SUB_A			0
#define SUB_B			1
#define SUB_C			2
#define SUB_D			3
#define SUB_MAX		4

// ip info
struct IPInfo {
  int       lev;
  uint32_t  ip;

  int    block;           // blocklist score

  TimeX  start_date;      // start range of access
  TimeX  end_date;        // end range of access

  float  elapsed;         // elapsed time (in mins)
  int    ip_cnt;          // number of ips in subnet
  int    page_cnt;        // number of pages touched
  int    uniq_cnt;        // number of unique pages

  int    num_days;
  int    num_robots;      // total robot.txt hits
  int    max_consecutive; // max consecutive days
  float  daily_min_hit;   // lowest hits per day
  float  daily_ave_hit;   // ave hits per day
  float  daily_max_hit;   // highest hits per day
  float  daily_min_ppm;   // lowest daily freq (pages/min)
  float	 daily_max_ppm;   // highest daily freq (pages/min)
  float  daily_min_range; // lowest daily range (start to end in hours)
  float	 daily_max_range; // highest daily range (start to end in hours)

  float  daily_pages;     // ave  # pages per day
  float  daily_uniq;      // uniq # pages per day
  float  uniq_ratio;
  float  visit_freq;
  float  visit_time;
  std::string  lookup[10];

  std::vector<LogInfo>	pages;	
};

struct DayInfo {
	DayInfo(TimeX day)		{ date=day; pages.clear(); }
	TimeX					date;
	IPInfo				metrics;
	std::vector<LogInfo>		pages;
};

typedef std::map<uint32_t, IPInfo >							IPMap_t;
typedef std::map<uint32_t, IPInfo>::iterator		IPMap_iter;

class LogRip : public Application {
public:
	virtual void startup();
	virtual bool init();
	virtual void display();

	void LoadLog ( std::string filename );
	void InsertLog(LogInfo i, int lev );
	void InsertIP(IPInfo i, int lev );
	void ProcessIPs( int lev );
	void PrepareDays ();
	void ClearDayInfo();
	void InsertDayInfo ( TimeX day, LogInfo& i );	
	void SortPagesByTime(std::vector<LogInfo>& pages);
	void SortPagesByName(std::vector<LogInfo>& pages);
	void ComputeDailyMetrics (IPInfo* f);
	void ComputeScore ( IPInfo* f );
	void LookupName (IPInfo* f);
	void ConstructIPHash();	
	void ConstructSubnet (int src_lev, int dest_lev);		
	void CreateImg (int xr, int yr);	
	void OutputPages( std::string filename );
	void OutputIPs(int outlev, std::string filename);
	void OutputIPs(int outlev, int lev, uint32_t parent, FILE* fp);
	void OutputHits (std::string filename);
	void OutputLoads (std::string filename);
	IPInfo* FindIP(uint32_t ip, int lev);

	TimeX			m_date_min;
	TimeX			m_date_max;
	int				m_total_days;

	std::vector< LogInfo >	m_Log;	

	IPMap_t									m_IPList[SUB_MAX];	

	std::vector< DayInfo >	m_DayList;

	ImageX		m_img[4];	
};

LogRip logrip;


uint32_t vecToIP(Vec4F v)
{	
	uint32_t i;
	i =  int(v.x) << 24;
  i += int(v.y) << 16;
	i += int(v.z) << 8;
  i += int(v.w);
	return i;
}
Vec4F ipToVec(uint32_t i)
{
	Vec4F v;
	v.x = (i & 0xFF000000) >> 24;
	v.y = (i & 0x00FF0000) >> 16;
	v.z = (i & 0x0000FF00) >> 8;
	v.w = (i & 0x000000FF);
	return v;
}
std::string ipToStr(uint32_t i)
{
	Vec4F v = ipToVec(i);
	std::string a,b,c,d;
  a = int(v.x) == 255 ? "*" : iToStr(int(v.x));
	b = int(v.y) == 255 ? "*" : iToStr(int(v.y));
	c = int(v.z) == 255 ? "*" : iToStr(int(v.z));
	d = int(v.w) == 255 ? "*" : iToStr(int(v.w));
	return  a+ "." + b + "." + c + "." + d;
}
bool memberOf(uint32_t ip, uint32_t parent)
{
	uchar pa = (parent & 0xFF000000) >> 24;
	uchar pb = (parent & 0x00FF0000) >> 16;
	uchar pc = (parent & 0x0000FF00) >> 8;
  uchar pd = (parent & 0x000000FF);
	int shift = (pa==0xFF) ? 32 : (pb==0xFF ? 24 : (pc==0xFF ? 16 : (pd==0x0FF) ? 8 : 0));
	if (shift==32) return true;
	uint32_t chk1 = (ip >> shift);
	uint32_t chk2 = (parent >> shift);
	return chk1==chk2;
}

uint32_t getMask(int lev)
{
	switch (lev) {
	case SUB_D:	return 0xFFFFFFFF;		break;
	case SUB_C:	return 0xFFFFFF00;		break;
	case SUB_B:	return 0xFFFF0000;		break;
	case SUB_A:	return 0xFF000000;		break;
	};
	return 0x00000000;
}

uint32_t getMaskedIP(uint32_t ip, int lev)
{
	uint32_t mask = getMask(lev);	
	uint32_t mip = (ip & mask) | (~mask & 0xFFFFFFFF);	
	return mip;
}


void LogRip::SortPagesByTime(std::vector<LogInfo>& pages)
{
	LogInfo tmp;

	// insertion sort (slow)
	for (int i = 0; i < pages.size(); i++) {
		for (int j = i+1; j < pages.size(); j++) {
			if (pages[j].date < pages[i].date) {
				tmp = pages[j]; pages[j] = pages[i]; pages[i] = tmp;		// swap
			}
		}
	}
}

void LogRip::SortPagesByName (std::vector<LogInfo>& pages)
{
	LogInfo tmp;

	// insertion sort (slow)
	for (int i = 0; i < pages.size(); i++) {
		for (int j = i+1; j < pages.size(); j++) {
			if (pages[j].page < pages[i].page) {
				tmp = pages[j]; pages[j] = pages[i]; pages[i] = tmp;		// swap
			}
		}
	}
}

void LogRip::LoadLog (std::string filename)
{
	char buf[16384];
	TimeX t;
	bool ok;
	std::string lin, page, ipstr, datestr, str;

	strncpy ( buf, filename.c_str(), 16384 );
	FILE* fp = fopen (buf, "r" );
	if (fp == 0x0) {
		printf ( "ERROR: Unable to open %s\n", filename.c_str() );
		return;
	}
	dbgprintf ( "Reading log: %s\n", filename.c_str() );

	int maxlog = 1e9;
	int cnt = 0;

	while (!feof(fp) && cnt < maxlog ) {		
		fgets ( buf, 16384, fp );
		lin = buf;
		// dbgprintf ("===== %s", lin.c_str() );
		
		/*
		// get page
		ok = strParseOutStr(lin, "\"GET", " HTTP/1", page, lin);
		if (!ok) continue;
		page = strTrim(page, " \"");

		// get IP
		ipstr = lin.substr(0, lin.find_first_of(' ') );
		Vec4F ipvec = strToVec4("<" + ipstr + ">", '.');
		
		// get datetime
		int mo;
		std::string str;
		ok = strParseOutStr(lin, "[", "+0000]", datestr, lin);
		if (!ok) continue;
		str = strSplitLeft ( datestr, "/" );
		int day = strToI( str );
		str = strSplitLeft ( datestr, "/" );
		if (str.compare("Jan")==0) mo = 1;
		else if (str.compare("Feb") == 0) mo = 2;
		else if (str.compare("Mar") == 0) mo = 3;
		else if (str.compare("Apr") == 0) mo = 4;
		else if (str.compare("May") == 0) mo = 5;
		else if (str.compare("Jun") == 0) mo = 6;
		else if (str.compare("Jul") == 0) mo = 7;
		else if (str.compare("Aug") == 0) mo = 8;
		else if (str.compare("Sep") == 0) mo = 9;
		else if (str.compare("Oct") == 0) mo = 10;
		else if (str.compare("Nov") == 0) mo = 11;
		else if (str.compare("Dec") == 0) mo = 12;
		str= strSplitLeft (datestr, ":");		int yr = strToI ( str );		
		str = strSplitLeft(datestr, ":");		int hr = strToI ( str );
		str = strSplitLeft(datestr, ":");		int min = strToI ( str );
		int sec = strToI( datestr.substr(0,2) );

    t.SetDateTime ( yr, mo, day, hr, min, sec );
		*/

		// dbgprintf("  %s: %s\n", datestr.c_str(), t.WriteDateTime().c_str());
	
		// get page
		ok = strParseOutStr(lin, "Started GET", "for ", page, lin);
		//dbgprintf("   lin: %s\n", lin.c_str() );
	  if (!ok) continue;
		page = strTrim (page, " \"" );

		// get IP
		strParseOutStr (lin, "for ", " at", ipstr, lin);						
		if (!ok) continue;
		
		Vec4F ipvec = strToVec4( "<"+ipstr+">", '.');				
		//dbgprintf("   %s: %d . %d . %d . %d\n", ipstr.c_str(), (int) ipvec.x, (int) ipvec.y, (int) ipvec.z, (int) ipvec.w );

		// get datetime	
		strParseOutStr (lin, "at ", "\n", datestr, lin);		
		if (!ok) continue;
		t.ReadDateTime ( datestr );  // assumes: YYYY-MM-DD HH:MM:SS
		//dbgprintf ( "  %s: %s\n", datestr.c_str(), t.WriteDateTime().c_str() );
		
		// all fields ok
		LogInfo li;
    	li.date = t;
		li.ip = vecToIP(ipvec);
		li.page = page;
		m_Log.push_back ( li );

		cnt++;

		//dbgprintf("log: %15s, %s, %s\n", li.page.c_str(), li.date.WriteDateTime().c_str(), ipToStr(li.ip).c_str());
	}

	

}


void LogRip::InsertLog ( LogInfo i, int lev )
{
	// find records
	IPMap_iter it;
	IPInfo info;

	IPMap_t& list = m_IPList[ lev ];

	// find or insert
	it = list.find(i.ip);
	if (it == list.end()) {
		it = list.insert(it, std::make_pair(i.ip, info));
		it->second.lev = lev;
		it->second.page_cnt = 0;
		it->second.start_date = i.date;
		it->second.end_date = i.date;
		it->second.ip_cnt = 1;
	}
	// update
	it->second.ip = i.ip;
	it->second.pages.push_back(i);
	it->second.page_cnt++;
	if (i.date < it->second.start_date)	it->second.start_date = i.date;
	if (i.date > it->second.end_date)		it->second.end_date = i.date;
}

IPInfo* LogRip::FindIP (uint32_t ip, int lev)
{
	IPMap_iter it;
	IPMap_t& list = m_IPList[lev];

	ip = getMaskedIP( ip, lev );

	it = list.find( ip );
	if (it==list.end()) return 0x0;

	return &it->second;
}


void LogRip::ConstructIPHash()
{
	// Insert raw log entries into D-level IP hash
	for (int n = 0; n < m_Log.size(); n++) {
		InsertLog (m_Log[n], SUB_D );
	}
}

void LogRip::PrepareDays()
{
	// determine date range of entire dataset
	IPMap_t& list = m_IPList[SUB_D];	

	m_date_min = list.begin()->second.start_date;
	m_date_max = list.begin()->second.end_date;

	std::map<uint32_t, IPInfo>::iterator it;
	for (it = list.begin(); it != list.end(); it++) {
		if (it->second.start_date < m_date_min)	m_date_min = it->second.start_date;
		if (it->second.end_date > m_date_max)		m_date_max = it->second.end_date;
	}	

	// prepare days structure
	m_date_min.ClearTime();
	m_date_max.ClearTime();	m_date_max.AdvanceDays(1); m_date_max.AdvanceSec(-1);
	m_total_days = m_date_max.GetElapsedDays(m_date_min) + 1;

	dbgprintf ( "  start date: %s\n", m_date_min.WriteDateTime().c_str() );
	dbgprintf ( "  end date:   %s\n", m_date_max.WriteDateTime().c_str() );
	dbgprintf ( "  total days: %d\n", m_total_days );
	
	TimeX curr_day = m_date_min;		// first day of data	

	for (int d = 0; d < m_total_days; d++) {
		m_DayList.push_back ( DayInfo(curr_day) );
		curr_day.AdvanceDays(1);
	}
}

void LogRip::ClearDayInfo()
{
	for (int d=0; d < m_total_days; d++)
		m_DayList[d].pages.clear ();
}

void LogRip::InsertDayInfo(TimeX date, LogInfo& i)
{
	//date.ClearTime();
	int day = date.GetElapsedDays ( m_date_min );

	//dbgprintf ( " DAY CHK: day#: %d, day, dmin: %s, daydate:%s, date:%s\n", day, m_date_min.WriteDateTime().c_str(), m_DayList[day].date.WriteDateTime().c_str(), date.WriteDateTime().c_str() );	
	assert( m_DayList[day].date.isSameDay( date ) );

	m_DayList[day].pages.push_back ( i );
}


void LogRip::ComputeDailyMetrics ( IPInfo* f)
{
	// daily metrics
	// - num_robots				all accesses to robots.txt
  // - max_consecutive	maximum consecutive days	
  // - elapsed					num elapsed days
	// - daily_min_hit		lowest hits per day
  // - daily_max_hit		highest hits per day  
	// - daily_min_ppm		lowest daily pages/min
	// - daily_max_ppm		highest daily pages/min
  // - daily_min_range	lowest daily range (start to end in hours)
	// - daily_max_range	highest daily range (start to end in hours)
	  
	LogInfo p, pl;
	int consecutive = 0;
	int daily_hits;
	float ave_ppm, range, ave_hits, gap;
	float dt;

	f->max_consecutive = 1;
	f->daily_min_hit = 10e10;
	f->daily_max_hit = 0;
	f->daily_min_ppm = 10e10;
	f->daily_max_ppm = 0;
	f->daily_min_range = 24*60;
	f->daily_max_range = 0;
	f->num_robots = 0;
	f->num_days = 0;
	f->daily_ave_hit = 0;

	ave_hits = 0;

	for (int d = 0; d < m_total_days; d++) {
		
		if (m_DayList[d].pages.size() > 0) {

			// count consecutive pages
			if (d==0 || m_DayList[d-1].pages.size() !=0 ) consecutive++; else consecutive = 0;
			if (consecutive > f->max_consecutive) f->max_consecutive = consecutive;

			// get daily metrics
			daily_hits = m_DayList[d].pages.size();
			p = m_DayList[d].pages[ daily_hits-1 ];
			pl = m_DayList[d].pages[0];			
			range = p.date.GetElapsedMin ( pl.date );		// range in minutes
			ave_hits += daily_hits;
			f->num_days++;
			
			// get each pages for: robot cnt, time deltas			
			ave_ppm = 0;
			gap = 0;
			for (int j=0; j < m_DayList[d].pages.size(); j++) {
				p = m_DayList[d].pages[j];
				if (p.page.find("robots.txt") != std::string::npos ) f->num_robots++;				
				if (j > 0) {
					dt = p.date.GetElapsedMin (pl.date);
					ave_ppm += dt;
					if (dt > gap) gap = dt;
				}				
				pl = p;				
			}
			ave_ppm = (daily_hits==1) ? 0 : (daily_hits - 1) / ave_ppm;

			range -= gap;

			// find metric min/max for each day
			if (daily_hits < f->daily_min_hit)	f->daily_min_hit = daily_hits;
			if (daily_hits > f->daily_max_hit)	f->daily_max_hit = daily_hits;
			if (daily_hits >= 3 ) {
					if (ave_ppm < f->daily_min_ppm) f->daily_min_ppm = ave_ppm;
					if (ave_ppm > f->daily_max_ppm) f->daily_max_ppm = ave_ppm;
					if (range < f->daily_min_range) f->daily_min_range = range;
					if (range > f->daily_max_range) f->daily_max_range = range;				
			}
		}
	}

	if (f->num_days > 0) ave_hits /= f->num_days;
	f->daily_pages = ave_hits;
	f->daily_ave_hit = ave_hits;
}


void LogRip::ComputeScore (IPInfo* f)
{	
	int block = 0;

	if (f->lev == SUB_C) {
		if (f->ip_cnt < 10) return;
		if (f->ip_cnt > 40) block = 5;
	} 
	
	if (f->lev == SUB_B) {
		if (f->ip_cnt < 20) return;
	}	

	//if (f->num_robots > 3 ) block = 5;
	if (f->daily_max_hit > 100) block = 4;
	if (f->daily_max_range > 6 * 60) block = 3;
	if (f->max_consecutive >= 5 && f->daily_max_range > 6*60) block = 2;
  if (f->daily_ave_hit > 20 && f->daily_max_ppm > 20 ) block = 1;

	if (f->lev == SUB_C && block != 1) block += 10;
	if (f->lev == SUB_B && block != 1) block += 20;

	f->block = block;
}


void LogRip::ProcessIPs( int lev )
{
	// Process IPs
	IPMap_t& list = m_IPList[ lev ];

	std::vector<float> diffs;

	std::map<uint32_t, IPInfo>::iterator it;

	for (it = list.begin(); it != list.end(); it++) {

		IPInfo* f = &it->second;		

		// sort pages by name for unique count
		SortPagesByName(f->pages);

		// count unique pages
		f->uniq_cnt = 1;
		for (int n = 1; n < f->pages.size(); n++) {
			if (f->pages[n].page != f->pages[n-1].page )
				f->uniq_cnt++;
		}

		// keep pages sorted by time 
		SortPagesByTime( f->pages );

		// get total elapsed 
		TimeX	curr_day = f->start_date; 
		curr_day.ClearTime();
		f->elapsed = f->end_date.GetElapsedDays(f->start_date);		
		
		// construct histogram by day
		ClearDayInfo ();		
		for (int n = 0; n < f->pages.size(); n++) {
			if (! f->pages[n].date.isSameDay ( curr_day ) ) {
				curr_day = f->pages[n].date;							// goto next day
				curr_day.ClearTime();	
			}			
			InsertDayInfo ( curr_day, f->pages[n] );
		}
		
		// compute daily metrics
		ComputeDailyMetrics ( f );

		// print day info (debugging)
		/* dbgprintf("START %s: %s\n", ipToStr(it->first).c_str(), curr_day.WriteDateTime().c_str());
		for (int d = 0; d < m_total_days; d++) {
			if (m_DayList[d].pages.size() > 0) {
				dbgprintf("  --> NEXT DAY: %s\n", m_DayList[d].date.WriteDateTime().c_str());
				for (int j = 0; j < m_DayList[d].pages.size(); j++) {
					dbgprintf("   %s, %s\n", m_DayList[d].pages[j].date.WriteDateTime().c_str(), m_DayList[d].pages[j].page.c_str());
				}
			}
		}
		dbgprintf ( "  METRICS %s\n", ipToStr(it->first).c_str());
		dbgprintf ( "  consecutive: %d\n", f->max_consecutive);
		dbgprintf ( "  robots.txt:  %d\n", f->num_robots);
		dbgprintf ( "  daily hits:  min %f, max %f (hits), AVE: %f (hits)\n", f->daily_min_hit, f->daily_max_hit, f->daily_ave_hit);
		dbgprintf ( "  daily ppm:   min %f, max %f (page/min)\n", f->daily_min_ppm, f->daily_max_ppm);
		dbgprintf ( "  daily range: min %f, max %f (mins)\n", f->daily_min_range, f->daily_max_range);   */
    

		if (f->daily_min_hit > 20 && f->daily_max_ppm > 20) {
		//	_getch();
		} 

		if (f->daily_max_hit > 100) {
		//	_getch();
		}
 

		// compute the page time deltas (frequency)
	  float d;
		diffs.clear ();
		for (int i = 1; i < f->pages.size(); i++) {
			d = f->pages[i].date.GetElapsedSec(f->pages[i-1].date);
			diffs.push_back ( d );
		}

		// get median (ignore outliers and time gaps)
		f->visit_freq = (diffs.size()==0) ? 0 : diffs[ diffs.size()/2 ];				// median
		f->visit_time = f->end_date.GetElapsedSec(f->start_date) / f->page_cnt;		// est. visit time
		f->elapsed = f->end_date.GetElapsedDays(f->start_date);		

		// Compute blocklist score
		ComputeScore ( f );

	}
}

void LogRip::InsertIP ( IPInfo i, int dest_lev )
{
	// find records
	IPMap_iter it;
	IPInfo info;
	IPInfo* f = 0x0;

	IPMap_t& list = m_IPList[dest_lev];

	// find or insert
	it = list.find (i.ip);
	if (it == list.end()) {
		it = list.insert(it, std::make_pair(i.ip, info));		
		f = &(it->second);
		f->lev = dest_lev;
		f->block = 0;
		f->start_date = i.start_date;
		f->end_date = i.end_date;
		f->daily_min_hit = i.daily_min_hit;
		f->daily_max_hit = i.daily_max_hit;
		f->daily_min_ppm = i.daily_min_ppm;
		f->daily_max_ppm = i.daily_max_ppm;
		f->daily_min_range = i.daily_min_range;
		f->daily_max_range = i.daily_max_range;
		f->max_consecutive = i.max_consecutive;
		f->num_robots = i.num_robots;
		f->visit_freq = 0;
		f->visit_time = 0;
		f->ip_cnt = 0;
		f->page_cnt = 0;
		f->uniq_cnt = 0;
	} else {
		f = &(it->second);
	}
	
  // update	
	f->ip = i.ip;

	for (int j=0; j < i.pages.size(); j++) {
		f->pages.push_back (i.pages[j]);
	}
	f->page_cnt += i.page_cnt;
	f->uniq_cnt += i.uniq_cnt;
	f->ip_cnt += i.ip_cnt;
	float cnt = f->ip_cnt;
	f->visit_freq = (f->visit_freq * float(cnt-1) + i.visit_freq)/cnt;
	f->visit_time = (f->visit_time * float(cnt-1) + i.visit_time)/cnt;
	f->daily_pages = (f->daily_pages * float(cnt-1) + i.daily_pages)/cnt;
	if (i.start_date < f->start_date)	f->start_date = i.start_date;
	if (i.end_date > f->end_date)		f->end_date = i.end_date;
	if (i.daily_min_hit < f->daily_min_hit)		f->daily_min_hit = i.daily_min_hit;
	if (i.daily_max_hit > f->daily_max_hit)		f->daily_max_hit = i.daily_max_hit;
	if (i.daily_min_ppm < f->daily_min_ppm)		f->daily_min_ppm = i.daily_min_ppm;
	if (i.daily_max_ppm > f->daily_max_ppm)		f->daily_max_ppm = i.daily_max_ppm;
	if (i.daily_min_range < f->daily_min_range) f->daily_min_range = i.daily_min_range;
	if (i.daily_max_range > f->daily_max_range) f->daily_max_range = i.daily_max_range;
	f->elapsed = f->end_date.GetElapsedDays(f->start_date);	
}

void LogRip::ConstructSubnet ( int src_lev, int dest_lev )
{
	Vec4F ipv;
	IPInfo i;	
	uint32_t mask;

	IPMap_t& src = m_IPList[src_lev];	
	mask = getMask(dest_lev);
	
	// insert all IPs into parent subnet	
	std::map<uint32_t, IPInfo>::iterator it;
	for (it = src.begin(); it != src.end(); it++) {
		IPInfo& f = it->second;
		i = f;

		// subnet ip		
		i.ip = getMaskedIP ( f.ip, dest_lev );		

		// insert into parent
		InsertIP (i, dest_lev );
	}
}


void LogRip::CreateImg(int xr, int yr)
{
	for (int i=0; i < I_NUM; i++)
		m_img[i].Resize( xr, yr, ImageOp::RGB8 );	
}

void LogRip::OutputHits ( std::string filename )
{
	int xr = m_img[0].GetWidth();
	int yr = m_img[0].GetHeight();
	char buf[16384];
	FILE* outcsv;

	int show_min = 1;
	int show_max = 29;
	
	strncpy ( buf, filename.c_str(), 16384);
	outcsv = fopen( buf , "wt");
	if (outcsv == 0x0) {
		dbgprintf("ERROR: Unable to open outhits.csv for writing.\n");
		exit(-1);
	}

	int first = 0;
	float first_tm = 10e10;
	for (int j=0; j < m_Log.size(); j++) {
		if ( m_Log[j].date.GetDays() < first_tm) {
			first = j;
			first_tm = m_Log[j].date.GetDays();
		}
	}
	sprintf ( buf, "firstdate, %s\n", m_Log[first].date.WriteDateTime().c_str() );
	fprintf ( outcsv, "%s", buf );

	m_img[I_ORIG].Fill(255, 255, 255, 255);	
	m_img[I_BLOCKED].Fill(255, 255, 255, 255);		
	m_img[I_FILTERED].Fill(255, 255, 255, 255);
	

	int x, x1, x2, y;
	Vec4F clr_orig, clr_block, clr_filter;
	IPInfo *fd, *fc, *fb;
	bool block;

	// day grid
	for (int d = 0; d < m_total_days; d++) {
		for (y=0; y < yr; y++) {
			x = d * xr / float(m_total_days);
			for (int i=0; i < I_NUM; i++)
				m_img[i].SetPixel ( x, y, Vec4F(128,128,128,255) );			
		}
	}
		
	for (int n = 0; n < m_Log.size(); n++) {
		
		LogInfo& i = m_Log[n];
	
		float tm = i.date.GetDays() - first_tm;
		Vec4F ipvec = ipToVec(i.ip);
		float ip = ipvec.x*256 + ipvec.y + (ipvec.z/256.0f);

		sprintf ( buf, "%f, %f\n", tm, ip );
		fprintf ( outcsv, "%s", buf );

		fd = FindIP ( i.ip, SUB_D );
		fc = FindIP ( i.ip, SUB_C );
		fb = FindIP ( i.ip, SUB_B );

		// graph point
		x = tm * xr / float(m_total_days);
		y = yr - ip * yr / float(224*256);			// use only 3/4 of graph area, where top is max IPv4 224.0.0.0 (above this is multicast/special)
		
		clr_orig = Vec4F(0,0,0, 255);	
		clr_block = Vec4F( 128, 128, 128, 255);
	    clr_filter = Vec4F( 0, 0, 0, 255);
		block = false;		
		
		// class D blocking
		if (fd->block >= show_min && fd->block <= show_max ) {
			clr_block.Set(255,0,0,255); block = true;
		}	else if (fd->block > 0 && fd->block < show_min) {
			clr_block.Set(240, 240, 240, 255); clr_orig = clr_block; block = true;
		}
		// class C blocking
		if (fc!=0x0 && fc->ip_cnt>1) {
			if (fc->block >= show_min && fc->block <= show_max ) { 
				clr_block.Set(255,0,255, 255); block = true; 
			} else if (fc->block > 0 && fc->block < show_min) {
				clr_block.Set(240, 240, 240, 255); clr_orig = clr_block; block = true;
			}
		}
		// class B blocking
		if (fb!=0x0 && fb->ip_cnt>10) {
			if (fb->block >= show_min && fb->block <= show_max ) {
				clr_block.Set(0, 0, 255, 255); block = true; 
			} else if (fb->block > 0 && fb->block < show_min) {
				clr_block.Set(240, 240, 240, 255); clr_orig = clr_block; block = true;
			}	
		}	

		m_Log[n].block = imax(fd->block, imax(fc->block, fb->block));
			
		if (block) clr_filter = clr_block;
		m_img[I_ORIG].Dot(x, y, 3.0, clr_orig );
		m_img[I_BLOCKED].Dot(x, y, 3.0, clr_block);
		if ( !block ) m_img[I_FILTERED].Dot(x, y, 3.0, clr_filter );		
	}

	fclose(outcsv);

	m_img[I_ORIG].Save( "out_fig1_orig.png");	
	m_img[I_BLOCKED].Save("out_fig2_blocked.png");
	m_img[I_FILTERED].Save( "out_fig3_filtered.png");
}

void LogRip::OutputLoads (std::string filename)
{
	int xr = m_img[0].GetWidth();
	int yr = m_img[0].GetHeight();
	m_img[I_ORIG].Fill(255, 255, 255, 255);

	int first = 0;
	float first_tm = 10e10;
	for (int j = 0; j < m_Log.size(); j++) {
		if (m_Log[j].date.GetDays() < first_tm) {
			first = j;
			first_tm = m_Log[j].date.GetDays();
		}
	}
	float ds, x, xl;
	float y[7], yl[7];
	int b;
	TimeX t;
	Vec4F pal[7];
	pal[0].Set(0, 0, 0, 255);			// no blocking - grey
	pal[1].Set(255,0,0,255);					// after throttle - red
	pal[2].Set(255,128,0,255);				// after consec - orange
	pal[3].Set(255,255, 0, 255);		  // after range - yellow
	pal[4].Set(0,  255, 0, 255);			// after daymax - green
  pal[5].Set(255, 0, 255, 255);     // after B net - purple
	pal[6].Set(0, 0, 255, 255);				// after C net - blue

	float load[7];
	for (int k = 0; k <= 6; k++) load[k] = 0;

	// load duration per hit
  // - this is the average server response time (impact) for a single hit
	float load_duration = 60;					// in seconds
	float vert_scale = 20;
	
	// plot 
	for (int x = 0; x < xr; x+= 4) {

		// get real datetime for this x-coord
		t = m_Log[first].date;
		t.AdvanceDays ( x * float(m_total_days) / xr );

		for (int k=0; k <= 6; k++) y[k] = 0;    

		// compute momentary load
		for (int n=0; n < m_Log.size(); n++) {			
			ds = m_Log[n].date.GetElapsedSec( t );			// delta in seconds
			b = m_Log[n].block;
			if (fabs(ds) < load_duration) {
				for (int k=0; k <= 6; k++) y[k]++;			// increase load
				if (b > 0 ) {
					if (b <= 1) y[1]--;				// throttle
					if (b <= 2) y[2]--;				// consecutive
					if (b <= 3) y[3]--;				// range
					if (b <= 4) y[4]--;				// daymax
					if (b <= 19) y[5]--;			// sub C
					if (b <= 29) y[6]--;			// sub B
				}
			}
		}	
		
		// accumulated load
		for (int k = 0; k <= 6; k++) load[k] += y[k];		

		// plot loads
		for (int k = 0; k <= 6; k++) {
			if (k >=1 && k <=5 ) continue;
			y[k] = (yr-1) - y[k] * vert_scale;
			m_img[I_ORIG].Line (xl, yl[k], x, y[k], pal[k] );
			yl[k] = y[k];
		}	
		xl = x;

	}

	for (int k = 0; k <= 6; k++) {
			dbgprintf ( "  %d, load: %f\n", k, load[k] );
	}

	m_img[I_ORIG].Save("out_load.png");
}


void LogRip::LookupName (IPInfo* f)
{
	// lookup IP 
	// HTTP		
	httplib::Client cli("http://ip-api.com");	
	std::string ipstr = "/line/" + ipToStr(f->pages[0].ip) + "?fields=status,country,regionName,city,zip,lat,long,isp,org,asname";
	auto res = cli.Get(ipstr.c_str());
	if (res->status == StatusCode::OK_200) {
		// parse out the 10 result strings: status,country,regionName,city,zip,lat,long,isp,org,asname
		std::string str = res->body;
		for (int n = 0; n < 10; n++) {
			f->lookup[n] = strSplitLeft(str, "\n");
		}
	}
        #ifdef _WIN32
	   Sleep(1500);   // ip-api, "This endpoint is limited to 45 queries per minute from an IP address"	
        #else
           sleep(1500);
        #endif
}

void LogRip::OutputIPs (int outlev, int lev, uint32_t parent, FILE* fp)
{
	char buf[16384];
	std::string str;
	IPMap_iter it;
	IPMap_t& list = m_IPList[lev];

	for (it = list.begin(); it != list.end(); it++) {

		if (memberOf(it->first, parent)) {
			IPInfo& f = it->second;
			// print IP
			
			if (lev == outlev) {

				// LookupName ( &f );

				std::string pagename = (lev==3) ? f.pages[0].page : "";			
				
				float day_freq = f.visit_freq / f.elapsed;			// # secs/day

				sprintf(buf, "%s, %d, %d, %d, %.2f, %.2f, %d, %d, %f, %f, %f, %f, %f, %f, %s, %s, %s, %s\n", 
														ipToStr(it->first).c_str(), f.ip_cnt, f.page_cnt, f.uniq_cnt, 
														(float) f.uniq_cnt /(float) f.page_cnt, f.elapsed, 
														f.max_consecutive, f.num_robots, 
														f.daily_min_hit, f.daily_max_hit, f.daily_min_ppm, f.daily_max_ppm, f.daily_min_range, f.daily_max_range, 
														f.lookup[L_ORG].c_str(), f.lookup[L_REGION].c_str(), f.lookup[L_COUNTRY].c_str(), pagename.c_str() );
				
				//if (f.ip_cnt > 1 || lev==3) {							
				if (fp!=0x0 ) fprintf(fp, "%s", buf);
				
				/*if (lev == 3) {
					// or print pages (level D)
					for (int j = 0; j < f.pages.size(); j++) {
						sprintf(buf, ",,,,,,%s,%s,,\n", f.pages[j].date.WriteDateTime().c_str(), f.pages[j].page.c_str() );
						dbgprintf("%s", buf);
						if (fp != 0x0) fprintf(fp, "%s", buf);
					}
				}*/
			}

			if (lev < 3 ) {
				// print children
				OutputIPs (outlev, lev + 1, it->first, fp);
			}	
		}
	}

}


void LogRip::OutputIPs (int outlev, std::string filename )
{	
	char fname[1024];
	FILE* outcsv = 0x0;

	strncpy(fname, filename.c_str(), 1024);
	outcsv = fopen( fname, "wt");
	if (outcsv == 0x0) {
		dbgprintf ( "ERROR: Unable to open %s for writing.\n", fname);
		exit(-1);
	}	
	// header 
	char buf[1024];	
	sprintf(buf, "IP, ip_cnt, page_cnt, uniq_cnt, uniq_ratio, elapsed(days), max_consec, num_robot, min_hit, max_hit, min_dt(sec), max_dt(sec), min_hr, max_hr, org, region, country, page\n");	

	if (outcsv != 0x0) fprintf(outcsv, "%s", buf);

	// recursive
	OutputIPs ( outlev, SUB_A, vecToIP(Vec4F(255,255,255,255)), outcsv );

	fclose (outcsv);
}

void LogRip::OutputPages (std::string filename)
{
	char fname[1024];
	FILE* outcsv = 0x0;

	strncpy(fname, filename.c_str(), 1024);
	outcsv = fopen(fname, "wt");
	if (outcsv == 0x0) {
		dbgprintf("ERROR: Unable to open %s for writing.\n", fname);
		exit(-1);
	}
	// header
	char buf[8192];
	sprintf (buf, "IP, pages, cnt, page\n");	
	if (outcsv != 0x0) fprintf(outcsv, "%s", buf);

	IPMap_iter it;
	IPMap_t& list = m_IPList[SUB_D];

	for (it = list.begin(); it != list.end(); it++) {

		IPInfo& f = it->second;

		// sort pages by name 
		SortPagesByName(f.pages);

		sprintf(buf, "%s, %d,,\n", ipToStr(it->first).c_str(), f.page_cnt );
		if (outcsv != 0x0) fprintf(outcsv, "%s", buf);

		// list unique pages
		int cnt = 1;
		for (int n = 1; n < f.pages.size(); n++) {
			if (f.pages[n].page == f.pages[n - 1].page) {
				cnt++;
			} else {
				sprintf(buf, ",,%d,%s\n", cnt, f.pages[n-1].page.c_str() );
				if (outcsv != 0x0) fprintf(outcsv, "%s", buf);
				cnt = 1;
			}	
		}
	}
	fclose ( outcsv );
}


bool LogRip::init()
{
  // load journalctl log

  printf ("LOGRIP\n");
  printf ("Copyright (c) 2024-2025, Quanta Sciences, Rama Hoetzlein\n");
  printf ("MIT License\n");

  std::string logfile = std::string(ASSET_PATH) + std::string("example_log.txt");
  
  LoadLog ( logfile );

  ConstructIPHash();

  PrepareDays ();

  ProcessIPs( SUB_D );

  ConstructSubnet ( SUB_D, SUB_C );

  ConstructSubnet ( SUB_C, SUB_B );

  ConstructSubnet ( SUB_B, SUB_A );

  ProcessIPs ( SUB_C );

  ProcessIPs ( SUB_B );

  // dbgprintf ( "Writing IPs.\n");
  OutputIPs ( SUB_D, "out_ips.csv");

  // dbgprintf("Writing Cnets.\n");
  OutputIPs ( SUB_C, "out_cnet.csv");
  // dbgprintf("Writing Pages.\n");
  OutputPages ( "out_pages.csv" );

  CreateImg ( 2480, 1024 );
  //CreateImg ( 8192, 4096 );

	// dbgprintf("Writing Hits.\n");
  OutputHits ( "out_hits.csv" );

  dbgprintf("Writing Loads.\n");
  OutputLoads ( "" );

  dbgprintf("Done.\n");

  exit(1);

  return true;
}

void LogRip::display()
{
  appPostRedisplay();
}

void LogRip::startup()
{
	appStart("Logrip (c) 2024-2025, Quanta Sciences", "logrip", 1024, 768, 3, 5, 16 );
}





