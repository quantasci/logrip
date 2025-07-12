
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
#include <regex>

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
#define I_NUM			  3

// log entry
struct LogInfo {
	void clear() {date.Clear(); page=""; ip=0; block=0; }
	bool isValid() {return (!date.isEmpty() && !page.empty() && ip > 0); }
	bool operator<(const LogInfo& other) const { return date < other.date; }
	TimeX					date;
	std::string		page;
	uint32_t			ip;
	char          block;
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

  int    score;           // blocklist score
  char   block;           // blocklist action

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
  void ComputeBlocklist ();
	void LookupName (IPInfo* f);
	void ConstructIPHash();	
	void ConstructSubnet (int src_lev, int dest_lev);		
	void CreateImg (int xr, int yr);	
  void OutputBlocklist (std::string filename);
	void OutputPages( std::string filename );
	int OutputIPs(int outlev, std::string filename);
	int OutputIPs(int outlev, int lev, uint32_t parent, FILE* fp);
	void OutputHits (std::string filename);
	void OutputVis ();
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
	i =  uint32_t(v.x) << 24;
  i += uint32_t(v.y) << 16;
	i += uint32_t(v.z) << 8;
  i += uint32_t(v.w);
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
  a = uint32_t(v.x) == 255 ? "*" : iToStr(uint32_t(v.x));
	b = uint32_t(v.y) == 255 ? "*" : iToStr(uint32_t(v.y));
	c = uint32_t(v.z) == 255 ? "*" : iToStr(uint32_t(v.z));
	d = uint32_t(v.w) == 255 ? "*" : iToStr(uint32_t(v.w));
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

	std::sort(pages.begin(), pages.end(), [](const LogInfo& a, const LogInfo& b) {
		return a.date < b.date;
	});

	// insertion sort (slow)
	/*for (int i = 0; i < pages.size(); i++) {
		for (int j = i+1; j < pages.size(); j++) {
			if (pages[j].date < pages[i].date) {
				tmp = pages[j]; pages[j] = pages[i]; pages[i] = tmp;		// swap
			}
		}
	}*/
}

void LogRip::SortPagesByName (std::vector<LogInfo>& pages)
{
	LogInfo tmp;

	std::sort(pages.begin(), pages.end(), [](const LogInfo& a, const LogInfo& b) {
		return a.page < b.page;
	});

	// insertion sort (slow)
	/* for (int i = 0; i < pages.size(); i++) {
		for (int j = i+1; j < pages.size(); j++) {
			if (pages[j].page < pages[i].page) {
				tmp = pages[j]; pages[j] = pages[i]; pages[i] = tmp;		// swap
			}
		}
	} */
}

#define	T_UNKNOWN					0
#define T_IP							1
#define T_NAME						2
#define T_PAGE						3
#define T_PLATFORM				4
#define	T_DATE_DDMMMYY		5
#define	T_DATE_YYYY_MM_DD	6
#define T_TIME_HHMMSS			7
#define T_RETURN					8
#define T_BYTES						9
#define T_NUM							10
#define T_GETPOST					11

struct TokenDef {	
	TokenDef(char t, std::string p)	{type=t; pattern=p;}
	char					type;
  std::string		pattern;
};
typedef std::vector<TokenDef>		defList;

// capture groups
std::unordered_map<std::string, TokenDef > tokenToRegex = 
{
		{"X.X.X.X",			{T_IP,						R"((\d+\.\d+\.\d+\.\d+))"}},
		{"AAA",					{T_NAME,					R"(([A-Za-z_\- ]+))"}},
		{"PAGE",				{T_PAGE,					R"((.*))"}},
    {"PLATFORM",		{T_PLATFORM,			R"((.*?))"}},
		{"DD/MMM/YYYY", {T_DATE_DDMMMYY,	R"((\d{2}/[A-Za-z]{3}/\d{4}))"}},
		{"YYYY-MM-DD",  {T_DATE_YYYY_MM_DD,	R"((\d{4}-\d{2}-\d{2}))"}},
		{"HH:MM:SS",		{T_TIME_HHMMSS,		R"((\d{2}:\d{2}:\d{2}))"}},
		{"RETURN",			{T_RETURN,				R"((\d+))"}},
		{"BYTES",				{T_BYTES,					R"((\d+))"}},
		{"NNN",					{T_NUM,						R"((\d+))"}},
		{"GET",					{T_GETPOST,				R"((\b(?:GET|POST|HEAD)\b))"}}
};

static const std::unordered_map<std::string, int> monthMap = {
		{"Jan", 1}, {"Feb", 2}, {"Mar", 3}, {"Apr", 4},
		{"May", 5}, {"Jun", 6}, {"Jul", 7}, {"Aug", 8},
		{"Sep", 9}, {"Oct",10}, {"Nov",11}, {"Dec",12}
};

std::string escapeLiteral(char c) 
{
	static const std::string regexSpecial = R"(\.^$|()[]*+?{})";
	if (regexSpecial.find(c) != std::string::npos) return "\\" + std::string(1, c);
	return std::string(1, c);
}

// dynamic parser
// - given a log format string with captured groups (eg. IP, DATE, PAGE)
// - construct a regex pattern that matches it (FormatToRegex)
// - then apply the regex pattern to every line of the input log file (ParseInput)
// - and convert the resulting matches into a loginfo struct (ConvertToLog)
//
std::string FormatToRegex(const std::string& format, defList& groupLabels) 
{
	std::string pattern;
	size_t i = 0;

	while (i < format.size()) {
		if (format[i] == '{') {
			size_t end = format.find('}', i);
			if (end == std::string::npos) throw std::runtime_error("Unmatched { in format");

			std::string token = format.substr(i + 1, end - i - 1);
			auto it = tokenToRegex.find(token);
			if (it != tokenToRegex.end()) {
				pattern += it->second.pattern;     // Capturing group
				groupLabels.push_back( TokenDef(it->second.type, token) );      // For result vector
			}
			else {
				throw std::runtime_error("Unknown token: " + token);
			}
			i = end + 1;
		} else if (format[i] == '*') {
			pattern += R"(.*?)";  // Non-capturing wildcard
			++i;
		}	else {
			pattern += escapeLiteral(format[i]);  // Exact literal match
			++i;
		}
	}
	return pattern;
}

std::vector<std::string> ParseInput(const std::string& pattern, const std::string& input) 
{
	std::regex rgx(pattern);
	std::smatch match;
	std::vector<std::string> results;

	if (std::regex_search(input, match, rgx)) {
		for (size_t i = 1; i < match.size(); ++i) {
			results.push_back(match[i].str());
		}
	}
	return results;
}

char ConvertToLog ( LogInfo& li, char typ, std::string str )
{
	int day, mo, yr, hr, min, sec;
	std::string val;
	size_t p1, p2, p3;
	Vec4F vec;

	switch (typ) {
	case T_IP:
		vec = strToVec4("<" + str + ">", '.');
		if (vec.x == 255 || vec.y == 255 || vec.z == 255 || vec.w == 255) {			// limitation of logrip, 255 not allowed as part of literal (specific) IP
			li.ip = 0;
			return 'i';		// printf("**** ERROR: %s\n  IP: %s", buf, str.c_str());			
		}
		else {
			li.ip = vecToIP(vec);
		}
		break;
	case T_DATE_DDMMMYY: {
		p1 = str.find_first_of('/');					if (p1 == std::string::npos) return 'd';
		p2 = str.find_first_of('/', p1 + 1);	if (p2 == std::string::npos) return 'd';
		day = strToI(str.substr(0, p1));
		val = str.substr(p1 + 1, p2 - p1 - 1); auto it = monthMap.find(val); mo = (it == monthMap.end()) ? 0 : it->second;
		yr = strToI(str.substr(p2 + 1));
		li.date.SetDate (mo, day, yr);
	} break;
	case T_DATE_YYYY_MM_DD: {
		p1 = str.find_first_of('-');					if (p1 == std::string::npos) return 'd';
		p2 = str.find_first_of('-', p1 + 1);		if (p2 == std::string::npos) return 'd';
		yr = strToI(str.substr(0, p1));
		mo = strToI(str.substr(p1 + 1, p2 - p1 - 1));
		day = strToI(str.substr(p2 + 1));
		li.date.SetDate(mo, day, yr);
	} break;
	case T_TIME_HHMMSS:
		p1 = str.find_first_of(':');					if (p1 == std::string::npos) return 't';
		p2 = str.find_first_of(':', p1 + 1);	if (p2 == std::string::npos) return 't';
		hr = strToI(str.substr(0, p1));
		min = strToI(str.substr(p1 + 1, p2 - p1 - 1));
		sec = strToI(str.substr(p2 + 1));
		li.date.SetTime(hr, min, sec);
		break;
	case T_PAGE:
		li.page = str;
		break;
	};
	return 1;
}

void LogRip::LoadLog (std::string filename)
{
	std::string lin, str, val;
	char buf[65535];	
	bool ok; 		
	std::string reason;
	Vec4F vec;
	LogInfo li;
	char ret;

	bool debug_parse = false;

	strncpy ( buf, filename.c_str(), 65535 );
	FILE* fp = fopen (buf, "r" );
	if (fp == 0x0) {
		printf ( "ERROR: Unable to open %s\n", filename.c_str() );
		return;
	}
	printf ( "Reading log: %s\n", filename.c_str() );

	int maxlog = 1e9;
	long perc = 0, percl = 0;
	long hits = 0, skipped = 0;
	char typ;

	fseek(fp, 0, SEEK_END);
	long size = 0;
  long max_size = ftell(fp)/1000;
	fseek(fp, 0, SEEK_SET);

	defList groupLabels;
	// std::string format = "{X.X.X.X} {AAA} {AAA} [{DD/MMM/YYYY}:{HH:MM:SS} +{NNN}] \"{GET} {PAGE}HTTP/*\" {RETURN} {BYTES} \"*\" {PLATFORM}";
	std::string format = "* Started {GET} \"{PAGE}\" for {X.X.X.X} at {YYYY-MM-DD} {HH:MM:SS}";
	std::string regexPattern = FormatToRegex ( format, groupLabels );

	while (!feof(fp) && hits < maxlog ) {

		// read next line
		fgets ( buf, 65535, fp );
		lin = buf;

		// report percentage complete
		size = ftell(fp)/1000;
		perc = (size*100)/max_size; 
		if ( (perc % 5)==0 && perc != percl) {
			percl = perc;
			printf ( " %ld%%. %ld read, %ld skipped.\n", perc, hits, skipped );
		}
		if (debug_parse) printf("\n===== %s", lin.c_str());

		// clear parsing 
		li.clear();				
		
		// parse this line
		std::vector<std::string> results = ParseInput ( regexPattern, lin );

		// process results
		for (int n = 0; n < results.size(); n++) {

			typ = groupLabels[n].type;
			str = results[n];			

			ret = ConvertToLog (li, typ, str);
		}
		
		// add item to log (if valid)
		if (li.isValid()) {
			if (debug_parse) printf("   OK. LOG: DATE=%s, IP=%s, PAGE=%s\n", li.date.WriteDateTime().c_str(), ipToStr(li.ip).c_str(), li.page.c_str());
			m_Log.push_back(li);
			hits++;

		}	else {
			skipped++;
			if (debug_parse) {
				if (results.size() == 0) reason = "Failed to match.";
				else if (ret == 'i') reason = "IP not handled (contains 255).";
				else if (li.ip == 0) reason = "No IP found.";
				else if (li.date.isEmpty()) reason = "No date found.";
				else if (li.page.empty()) reason = "No page found."; 
			  printf("   SKIPPED. Reason: %s\n", reason.c_str() );
			}
		}
		
	}

	printf("\n" );

	if (m_Log.size() == 0) {
		printf ("**** ERROR: No logs found. Log format may be different.\n");
		exit(-2);
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

	dbgprintf ( "Start date: %s\n", m_date_min.WriteDateTime().c_str() );
	dbgprintf ( "End date:   %s\n", m_date_max.WriteDateTime().c_str() );
	dbgprintf ( "Total days: %d\n", m_total_days );
	
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
	f->daily_min_hit = 1e7;
	f->daily_max_hit = 0;
	f->daily_min_ppm = 1e7;
	f->daily_max_ppm = 0;
	f->daily_min_range = 1440;
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

	if (f->daily_min_hit == 1e7) f->daily_min_hit = 0;	
	if (f->daily_min_ppm == 1e7) f->daily_min_ppm = 0;
	if (f->daily_max_ppm == 1e7) f->daily_max_ppm = 0;
	if (f->daily_min_range == 1440) f->daily_min_range = 0;
	if (f->num_days > 0) ave_hits /= f->num_days;
	f->daily_pages = ave_hits;
	f->daily_ave_hit = ave_hits;
}


void LogRip::ComputeScore (IPInfo* f)
{	
	// blocking score
  // example:	
  // +1  rate throttle (daily hit > 20, ppm > 20)
	// +2  consecusive metric (days > 5, hr/day > 6)
	// +3  daily range (hr/day > 6)
	// +4  day thottle (hits/day > 100)
  // +5  subnet (# ips > 40)
	// +10 subnet C (/w any other blocking)
	// +20 subnet B (/w any other blocking)

  int min_ip_b = 10;
  int min_ip_c = 3;
  int max_ip_c = 40;

	int score = 0;

  if (f->lev == SUB_B && f->ip_cnt < min_ip_b) return;
	if (f->lev == SUB_C && f->ip_cnt < min_ip_c) return;
  
  if (f->lev == SUB_C && f->ip_cnt > max_ip_c) score = 6;
  if (f->num_robots > 3 ) score = 5;
	if (f->daily_max_hit > 100) score = 4;
	if (f->daily_max_range > 6 * 60) score = 3;
	if (f->max_consecutive >= 5 && f->daily_max_range > 4*60) score = 2;
  if (f->daily_ave_hit > 20 && f->daily_max_ppm > 20 ) score = 1;

	f->score = score;
  
  f->block = 0;  // blocking action not computed here
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
		f->score = 0;
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
	char buf[16384];
	FILE* outcsv;	

	strncpy ( buf, filename.c_str(), 16384);
	outcsv = fopen( buf , "wt");
	if (outcsv == 0x0) {
		dbgprintf("ERROR: Unable to open outhits.csv for writing.\n");
		exit(-1);
	}
	// compute starting time
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
		
	for (int n = 0; n < m_Log.size(); n++) {
		
		LogInfo& i = m_Log[n];
	
		float tm = i.date.GetDays() - first_tm;
		Vec4F ipvec = ipToVec(i.ip);
		float ip = ipvec.x*256 + ipvec.y + (ipvec.z/256.0f);

		sprintf ( buf, "%f, %f\n", tm, ip );
		fprintf ( outcsv, "%s", buf );
	}

	fclose(outcsv);
}


void LogRip::ComputeBlocklist ()
{
  IPMap_t* list;
	std::map<uint32_t, IPInfo>::iterator it;
  IPInfo* f;
  IPInfo *fb, *fc, *fd;

  int score_min = 1;
  int score_max = 29;

  // Class B Blocking
	list =  &m_IPList[ SUB_B ];
	for (it = list->begin(); it != list->end(); it++) {
    fb = &it->second;	
    if (fb->score >= score_min && fb->score <= score_max ) {
				fb->block = 'B';        // block by B subnet, highest level (we don't block at A subnet level)
    }
	}

  // Class C Blocking
	list =  &m_IPList[ SUB_C ];
	for (it = list->begin(); it != list->end(); it++) {
    fc = &it->second;
    fb = FindIP(fc->ip, SUB_B);
    if (fb != 0x0 && fb->block !=0 ) {
      fc->block = fb->block;  // block by parent
    } else if (fc->score >= score_min && fc->score <= score_max ) {
      fc->block = 'C';        // block by C-net
    }
	}

  // IP-Level Blocking
	list =  &m_IPList[ SUB_D ];
	for (it = list->begin(); it != list->end(); it++) {
    fd = &it->second;	
    fc = FindIP(fd->ip, SUB_C);
    if (fc != 0x0 && fc->block !=0 ) {
      fd->block = fc->block;    // block by parent
    } else if (fd->score >= score_min && fd->score <= score_max ) {
      fd->block = 'I';          // block IP
    }
	}

  // Map IP blocklist back to log events 
	for (int n = 0; n < m_Log.size(); n++) {
		LogInfo& i = m_Log[n];
    // find IP 
		fd = FindIP(i.ip, SUB_D);
    m_Log[n].block = fd->block;
  }

}

void LogRip::OutputBlocklist (std::string filename)
{
	char buf[16384];
	FILE* fp;	

	strncpy ( buf, filename.c_str(), 16384);
	fp = fopen( buf , "wt");
	if (fp == 0x0) {
		dbgprintf("ERROR: Unable to open %s for writing.\n", filename.c_str() );
		exit(-1);
	}

  IPMap_t* list;
	std::map<uint32_t, IPInfo>::iterator it;
  IPInfo* f;
  
  // Class B Blocking
	list =  &m_IPList[ SUB_B ];
	for (it = list->begin(); it != list->end(); it++) {
    f = &it->second;	
    if (f->block == 'B') fprintf (fp, "%s/16\n", ipToStr(f->ip).c_str());
	}

  // Class C Blocking
	list =  &m_IPList[ SUB_C ];
	for (it = list->begin(); it != list->end(); it++) {
    f = &it->second;
    if (f->block =='C') fprintf (fp, "%s/24\n", ipToStr(f->ip).c_str() );
	}

  // IP-Level Blocking
	list =  &m_IPList[ SUB_D ];
	for (it = list->begin(); it != list->end(); it++) {
    f = &it->second;	
    if (f->block =='I') fprintf (fp, "%s\n", ipToStr(f->ip).c_str() );
	}

  fclose(fp);
}

void LogRip::OutputVis ()
{
	int xr = m_img[0].GetWidth();
	int yr = m_img[0].GetHeight();	

	int show_min = 1;
	int show_max = 29;

	// compute starting time
	int first = 0;
	float first_tm = 10e10;
	for (int j = 0; j < m_Log.size(); j++) {
		if (m_Log[j].date.GetDays() < first_tm) {
			first = j;
			first_tm = m_Log[j].date.GetDays();
		}
	}
	m_img[I_ORIG].Fill(255, 255, 255, 255);
	m_img[I_BLOCKED].Fill(255, 255, 255, 255);
	m_img[I_FILTERED].Fill(255, 255, 255, 255);

  Vec4F black(0,0,0,255);

	int x, x1, x2, y;
	Vec4F clr_block;
	IPInfo *f;

	// day grid
	for (int d = 0; d < m_total_days; d++) {		
		x = d * xr / float(m_total_days);
		for (int i = 0; i < I_NUM; i++) {
			m_img[i].Line(x, 0, x, yr, Vec4F(0,128,0,255) );
		}
	}

	for (int n = 0; n < m_Log.size(); n++) {

		LogInfo& i = m_Log[n];
    // get time & ip
		float tm = i.date.GetDays() - first_tm;
		Vec4F ipvec = ipToVec(i.ip);
		float ip = ipvec.x * 256 + ipvec.y + (ipvec.z / 256.0f);
		
		// graph point
		x = tm * xr / float(m_total_days);    // x-axis = time
		y = yr - ip * yr / float(224 * 256);	// y-axis = ip,   mask off above IPv4 224.0.0.0 (multicast/special area)

		clr_block = Vec4F(128, 128, 128, 255);

		// set vis color based on blocking level
		switch (i.block) {
    case 'B': clr_block.Set(0, 0, 255, 255); break;
    case 'C': clr_block.Set(255, 0, 255, 255); break;
    case 'I': clr_block.Set(255, 0, 0, 255); break;
    }
    
    // plot results:
    // original image - all IPs, always black
		m_img[I_ORIG].Dot(x, y, 3.0, black);
    // blocked image - action taken
		m_img[I_BLOCKED].Dot(x, y, 3.0, clr_block);
    // filtered image - only those not blocked 
		if (i.block==0) m_img[I_FILTERED].Dot(x, y, 3.0, black);
	}

	m_img[I_ORIG].Save("out_fig1_orig.png");
	m_img[I_BLOCKED].Save("out_fig2_blocked.png");
	m_img[I_FILTERED].Save("out_fig3_filtered.png");
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
	pal[0].Set(120, 120, 120, 255);			// no blocking - grey
	pal[1].Set(255,0,0,255);					// after throttle - red
	pal[2].Set(255,128,0,255);				// after consec - orange
	pal[3].Set(255,255, 0, 255);		  // after range - yellow
	pal[4].Set(0,  255, 0, 255);			// after daymax - green
  pal[5].Set(255, 0, 255, 255);     // after B net - purple
	pal[6].Set(0, 0, 255, 255);				// after C net - blue

	float load[7];
	for (int k = 0; k <= 6; k++) {
		load[k] = 0;
		yl[k] = 0;
	}

	// day grid
	for (int d = 0; d < m_total_days; d++) {
		x = d * xr / float(m_total_days);
		for (int i = 0; i < I_NUM; i++) {
			m_img[i].Line(x, 0, x, yr, Vec4F(0, 128, 0, 255));
		}
	}

	// load duration per hit
  // - this is the average server response time (impact) for a single hit
	float load_duration = 120;					// in seconds
	float vert_scale = 60;	
	
	// plot 
	xl = 0;
	for (x = 0; x < xr; x++) {

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
		for (int k = 0; k <= 6; k++) {
			load[k] += y[k];					
		}		

		// plot loads
		for (int k = 0; k <= 6; k++) {
			if (k >=1 && k <=5 ) continue;
			y[k] = (yr-1) - y[k] * vert_scale;
			//m_img[I_ORIG].Line (xl, yl[k], x, y[k], pal[k] );
			m_img[I_ORIG].Line (x, yr, x, y[k], pal[k] );
			yl[k] = y[k];
		}	
		xl = x;
	}

	/*for (int k = 0; k <= 6; k++) {
			dbgprintf ( "  %d, load: %f\n", k, load[k] );
	}*/

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

int LogRip::OutputIPs(int outlev, int lev, uint32_t parent, FILE* fp)
{
	char buf[2048];	
	IPMap_iter it;
	IPMap_t& list = m_IPList[lev];
	IPInfo* f;
	int cnt = 0;

	for (it = list.begin(); it != list.end(); it++) {

		if (!memberOf(it->first, parent)) continue;

		if (lev == outlev) {
			// print ip info
			f = &it->second;

			// LookupName ( &f );

			Vec4F ipv = ipToVec( it->first );
			Vec4F ipp = ipToVec( parent );
			if (ipv.x==92 && ipv.y==28 && ipv.z==82 && ipv.w==214) {
			bool stop=true;
		}
			const std::string& ipstr = ipToStr(it->first);			
			const char* pagename = "";
			if (lev == 3 && !f->pages.empty()) { pagename = f->pages[0].page.c_str(); }

			float day_freq = f->visit_freq / f->elapsed;			// # secs/day
			float uniq_ratio = (f->page_cnt > 0) ? ((float)f->uniq_cnt / f->page_cnt) : 0.0f;

			snprintf(buf, 2048, "%s, %d, %d, %d, %.2f, %.2f, %d, %d, %f, %f, %f, %f, %f, %f, %s, %s, %s, %s\n",
				ipstr.c_str(), f->ip_cnt, f->page_cnt, f->uniq_cnt,
				uniq_ratio, f->elapsed,
				f->max_consecutive, f->num_robots,
				f->daily_min_hit, f->daily_min_range/60.0, f->daily_min_ppm, f->daily_max_hit, f->daily_max_range/60.0, f->daily_max_ppm,
				f->lookup[L_ORG].c_str(), f->lookup[L_REGION].c_str(), f->lookup[L_COUNTRY].c_str(), pagename );
						
			if (fp) fwrite(buf, 1, strlen(buf), fp);

			cnt++;
		
		} else if (lev < 3) {

			// print children
			cnt += OutputIPs(outlev, lev + 1, it->first, fp);
		}		
	}

	return cnt;
}

int LogRip::OutputIPs (int outlev, std::string filename )
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
	sprintf(buf, "IP, ip_cnt, page_cnt, uniq_cnt, uniq_ratio, elapsed(days), max_consec, num_robot, min_hit, min_hr, min_ppm, max_hit, max_hr, max_ppm, org, region, country, page\n");	

	if (outcsv != 0x0) fprintf(outcsv, "%s", buf);

	// recursive
	int cnt = OutputIPs ( outlev, SUB_A, vecToIP(Vec4F(255,255,255,255)), outcsv );	

	fclose (outcsv);

	return cnt;
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
	int cnt;

  // load journalctl log

  dbgprintf ("LOGRIP\n");
  dbgprintf ("Copyright (c) 2024-2025, Quanta Sciences, Rama Hoetzlein\n");
  dbgprintf ("MIT License\n\n");

  //std::string logfile = std::string(ASSET_PATH) + std::string("csi_log_2025_02_12.txt");
  std::string logfile = std::string(ASSET_PATH) + std::string("example_log.txt");
  
  LoadLog ( logfile );

	dbgprintf("Construct IP Hash.\n");
  ConstructIPHash();

	dbgprintf("Preparing Days.\n");
  PrepareDays ();

	dbgprintf("Processing IPs.\n");
  ProcessIPs( SUB_D );

	dbgprintf ( "Constructing C-Subnets.\n");
  ConstructSubnet ( SUB_D, SUB_C );

	dbgprintf ( "Constructing B-Subnets.\n");
  ConstructSubnet ( SUB_C, SUB_B );

	dbgprintf ( "Constructing A-Subnets.\n");
  ConstructSubnet ( SUB_B, SUB_A );

	dbgprintf ( "Processing IPs. C-Subnets.\n");
  ProcessIPs ( SUB_C );

	dbgprintf ( "Processing IPs. B-Subnets.\n");
  ProcessIPs ( SUB_B );

  dbgprintf ( "Computing Blocklist.\n");
  ComputeBlocklist ();

  dbgprintf ( "Writing Blocklist.\n");
  OutputBlocklist ( "out_blocklist.txt" );

	dbgprintf ( "Writing IPs (B-Subnets)... ");
	cnt = OutputIPs(SUB_B, "out_ips_bnet.csv");
	printf("%d ips.\n", cnt);

  dbgprintf ( "Writing IPs (C-Subnets)... ");
  cnt = OutputIPs ( SUB_C, "out_ips_cnet.csv");
	printf("%d ips.\n", cnt);

	dbgprintf ( "Writing IPs (All Mach)... ");
	cnt = OutputIPs(SUB_D, "out_ips.csv");
	printf("%d ips.\n", cnt);
	
  dbgprintf ( "Writing Pages.\n");
  OutputPages ( "out_pages.csv" );

  //CreateImg ( 2480, 1024 );
  CreateImg ( 4096, 2048 );

	dbgprintf ( "Writing Hits.\n");
  OutputHits ( "out_hits.csv" );

	dbgprintf ( "Writing Visualizations.\n");
	OutputVis ();

  dbgprintf ( "Writing Loads.\n");
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





