//--------------------------------------------------------------------------------
// 
// LOGRIP
// Defend against AI crawlers and bots with server log analysis
// 
// Copyright 2024-2025 (c) Quanta Sciences, Rama Hoetzlein
// https://github.com/quantasci/logrip
// https://ramakarl.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//--------------------------------------------------------------------------------

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

// lookup fields
#define L_STATUS    0
#define L_COUNTRY   1
#define L_REGION    2
#define L_CITY      3
#define L_ZIP       4
#define L_LAT       5
#define L_LONG      6
#define L_ISP       7
#define L_ORG       8
#define L_ASNAME    9

// image types
#define I_ORIG      0
#define I_BLOCKED   1
#define I_FILTERED  2
#define I_NUM       3

// config fields
int CONF_FORMAT =         0;
int CONF_DEBUGPARSE =     1;
int CONF_REASONS =        2;
int CONF_MIN_IPB =        3;
int CONF_MIN_IPC =        4;
int CONF_MAX_IPC =        5;
int CONF_MAX_ROBOT =      6;
int CONF_MAX_DAILY_HITS =  7;
int CONF_MAX_DAILY_RANGE = 8;
int CONF_MAX_CONSEC_DAYS = 9;
int CONF_MAX_CONSEC_RANGE = 10;
int CONF_MAX_DAILY_AVE =  11;
int CONF_MAX_DAILY_PPM =  12;
int CONF_LOAD_DURATION =  13;
int CONF_LOAD_SCALE =     14;
int CONF_VIS_RES =        15;
int CONF_VIS_ZOOM =       16;


enum class ValueType {
  STRING,
  FLOAT,
  BOOL,
  INT,
  VEC4F,
};

// typeless value (C++11 compatible)
class Value {
public:
  Value() {type=ValueType::STRING; s=""; b=false; i=0;}
  Value(const std::string& str) : type(ValueType::STRING), s(str) {}
  Value(float val)  : type(ValueType::FLOAT), f(val) {}
  Value(bool val)   : type(ValueType::BOOL),  b(val) {}
  Value(int val)    : type(ValueType::INT),   i(val) {}
  Value(const Vec4F& v) : type(ValueType::VEC4F), vec(v) {}
  Value(const Value& other) { *this = other; }
  void SetValue(const std::string& str);
  Value& operator=(const Value& other) {
    if (this != &other) {
        type = other.type;
        switch (type) {
        case ValueType::STRING: s = other.s; break;
        case ValueType::BOOL:   b = other.b; break;
        case ValueType::INT:    i = other.i; break;
        case ValueType::FLOAT:  f = other.f; break;
        case ValueType::VEC4F:  vec = other.vec; break;
        }
    }
    return *this;
  }
  ValueType   type;
  std::string s;
  union 
  {
    float     f;
    bool      b;
    int       i;
    Vec4F     vec;
  };
};

// config key-value
struct ConfigEntry {
  int           key;
  std::string   name;
  ValueType     type;
  Value         val;  
};

// log entry
struct LogInfo {
  void clear() {date.Clear(); page=""; ip=0; block=0; }
  bool isValid() {return (!date.isEmpty() && !page.empty() && ip > 0); }
  bool operator<(const LogInfo& other) const { return date < other.date; }
  TimeX         date;
  std::string   page;
  uint32_t      ip;
  char          block;
};


// subnets
#define SUB_A     0
#define SUB_B     1
#define SUB_C     2
#define SUB_D     3
#define SUB_MAX   4

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
  float  daily_max_ppm;   // highest daily freq (pages/min)
  float  daily_min_range; // lowest daily range (start to end in hours)
  float  daily_max_range; // highest daily range (start to end in hours)

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
  TimeX   date;
  IPInfo  metrics;
  Vec3I   stats;
  std::vector<LogInfo>  pages;
};

typedef std::map<uint32_t, IPInfo >             IPMap_t;
typedef std::map<uint32_t, IPInfo>::iterator    IPMap_iter;

class LogRip : public Application {
  public:
  virtual void startup();
  virtual bool init();
  virtual void display();
  virtual void on_arg(int i, std::string arg, std::string val);

  // config file
  void LoadConfig ( std::string filename );
  void SetConfigValue (const std::string& name, std::string value );
  void SetDefaultConfig ();
  Value getVal(int k, ValueType t);
  float getF(int k) { Value v = getVal(k, ValueType::FLOAT); return v.f; }
  int   getI(int k) { Value v = getVal(k, ValueType::INT);   return v.i; }
  bool  getB(int k) { Value v = getVal(k, ValueType::BOOL);  return v.b; }
  Vec4F getV4(int k) { Value v = getVal(k, ValueType::VEC4F); return v.vec; }
  std::string getStr(int k) { Value v = getVal(k, ValueType::STRING); return v.s; }

  // loading logs
  void LoadLog ( std::string filename );
  void InsertLog(LogInfo i, int lev );
  void InsertIP(IPInfo i, int lev );
  void ProcessIPs( int lev );
  void PrepareDays ();
  void ClearDayInfo();
  void InsertDayInfo ( TimeX day, LogInfo& i );	
  void SortPagesByTime(std::vector<LogInfo>& pages);
  void SortPagesByName(std::vector<LogInfo>& pages);

  // compute metrics & blocklist
  void ComputeDailyMetrics (IPInfo* f);
  void ComputeScore ( IPInfo* f );
  void ComputeBlocklist ();
  void LookupName (IPInfo* f);
  void ConstructIPHash();	
  void ConstructSubnet (int src_lev, int dest_lev);
  void CreateImg (int xr, int yr);

  // output results
  void OutputBlocklist (std::string filename);
  void OutputPages( std::string filename );
  int OutputIPs(int outlev, std::string filename);
  int OutputIPs(int outlev, int lev, uint32_t parent, FILE* fp);
  void OutputHits (std::string filename);
  void OutputStats (std::string filename, std::string imgname);
  void OutputVis ();
  void OutputLoads (std::string filename);
  IPInfo* FindIP(uint32_t ip, int lev);

  TimeX       m_date_min;
  TimeX       m_date_max;
  int         m_total_days;

  std::string m_log_file;
  std::string m_conf_file;

  std::vector< LogInfo >  m_Log;

  IPMap_t                 m_IPList[SUB_MAX];	

  std::vector< DayInfo >  m_DayList;

  std::vector<ConfigEntry> m_Config;

  ImageX      m_img[4];

  char        m_buf[65535];
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
std::string ipToStr(uint32_t i, char wild='*' )
{
  Vec4F v = ipToVec(i);
  std::string a,b,c,d;
  a = uint32_t(v.x) == 255 ? std::string(1, wild) : iToStr(uint32_t(v.x));
  b = uint32_t(v.y) == 255 ? std::string(1, wild) : iToStr(uint32_t(v.y));
  c = uint32_t(v.z) == 255 ? std::string(1, wild) : iToStr(uint32_t(v.z));
  d = uint32_t(v.w) == 255 ? std::string(1, wild) : iToStr(uint32_t(v.w));
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

void Value::SetValue ( const std::string& str)
{
  switch ( type ) {
  case ValueType::BOOL:   b = (str=="1") ? true : false; break;
  case ValueType::FLOAT:  f = strToF(str); break;
  case ValueType::INT:    i = strToI(str); break;
  case ValueType::STRING: s = str; break;
  case ValueType::VEC4F:  vec = strToVec4("<"+str+">", ','); break;
  }
}
Value LogRip::getVal(int k, ValueType t) 
{ 
  ConfigEntry& e = m_Config[k];
  if (e.val.type!=t ) {
    printf ("ERROR: Unexpected type.\n" );
    exit(-4);
  }
  return e.val;
}


void LogRip::SetConfigValue (const std::string& name, std::string value )
{
  for (int i=0; i < m_Config.size(); i++) {
    if (m_Config[i].name == name) {
     if (i != m_Config[i].key) {
       printf ("ERROR: Config list order in LoadConfig must match CONF const order.\n");
       exit(-77);
     }
     m_Config[i].val.type = m_Config[i].type;   // assign type to value
     m_Config[i].val.SetValue(value);           // set the value
     printf ( " Set: %s = %s\n", name.c_str(), value.c_str() );
     return;
    }
  }
  printf ("**** ERROR: Config key %s not known. Ignored.\n", name.c_str() );
}

void LogRip::SetDefaultConfig ()
{
  SetConfigValue ( "format", "{X.X.X.X} {AAA} {AAA} [{DD/MMM/YYYY}:{HH:MM:SS} +{NNN}] \"{GET} {PAGE}HTTP/*\" {RETURN} {BYTES} \"*\" {PLATFORM}" );
  SetConfigValue ( "debugparse", "0");
}

void LogRip::LoadConfig ( std::string filename )
{
  // setup config key & values
  // config var             config key string   type    default
  m_Config = {
    {CONF_FORMAT,           "format",           ValueType::STRING, Value(std::string("")) },
    {CONF_DEBUGPARSE,       "debugparse",       ValueType::BOOL,   Value(false) },
    {CONF_REASONS,          "reasons",          ValueType::BOOL,   Value(false) },
    {CONF_MIN_IPB,          "min_ip_b",         ValueType::INT,    Value(1024) },
    {CONF_MIN_IPC,          "min_ip_c",         ValueType::INT,    Value(3) },
    {CONF_MAX_IPC,          "max_ip_c",         ValueType::INT,    Value(80) },
    {CONF_MAX_ROBOT,        "max_robot",        ValueType::INT,    Value(10) },
    {CONF_MAX_DAILY_HITS,   "max_daily_hits",   ValueType::INT,    Value(100) },
    {CONF_MAX_DAILY_RANGE,  "max_daily_range",  ValueType::INT,    Value(360) },
    {CONF_MAX_CONSEC_DAYS,  "max_consec_days",  ValueType::INT,    Value(5) },
    {CONF_MAX_CONSEC_RANGE, "max_consec_range", ValueType::INT,    Value(240) },
    {CONF_MAX_DAILY_AVE,    "max_daily_ave",    ValueType::INT,    Value(100) },
    {CONF_MAX_DAILY_PPM,    "max_daily_ppm",    ValueType::FLOAT,  Value(5) },
    {CONF_LOAD_DURATION,    "load_duration",    ValueType::FLOAT,  Value(80) },
    {CONF_LOAD_SCALE,       "load_scale",       ValueType::FLOAT,  Value(40) },
    {CONF_VIS_RES,          "vis_res",          ValueType::VEC4F,  Value( Vec4F(2048,1024,0,0) ) },
    {CONF_VIS_ZOOM,         "vis_zoom",         ValueType::VEC4F,  Value(Vec4F(0,0,1000,224)) }
  };

  if (filename.empty()) {
    printf ("**** WARNING: No config file specified.\n" );
    printf ( "Using default config (Apache2).\n");
    SetDefaultConfig ();
    return;
  }
  std::string conf_file;
  if (!getFileLocation(filename, conf_file)) {
    printf ( "**** ERROR: Unable to find or open config file: %s\n", filename.c_str() );
    exit(-1);
  }  

  printf ("Loading config: %s\n", conf_file.c_str() );

  // read config file  
  std::string key, val;  
  FILE* fp = fopen (conf_file.c_str(), "r" );
  if (fp == 0x0) {
    printf ( "**** ERROR: Unable to open %s\n", filename.c_str() );
    printf ( "Using default config (Apache2).\n");
    SetDefaultConfig ();
    return;
  }
  while (!feof(fp)) {
    fgets ( m_buf, 2048, fp );
    val = m_buf;

    key = strSplitLeft ( val, ":" );
    val = strTrim(val);
    if (!val.empty()) SetConfigValue ( key, val );
  }

  std::string format = getStr(CONF_FORMAT);
  printf (" Using format: %s\n", format.c_str() );
  printf ("\n");
}


void LogRip::SortPagesByTime(std::vector<LogInfo>& pages)
{
  LogInfo tmp;

  std::sort(pages.begin(), pages.end(), [](const LogInfo& a, const LogInfo& b) {
    return a.date < b.date;
  });
}

void LogRip::SortPagesByName (std::vector<LogInfo>& pages)
{
  LogInfo tmp;

  std::sort(pages.begin(), pages.end(), [](const LogInfo& a, const LogInfo& b) {
    return a.page < b.page;
  });
}

#define T_UNKNOWN         0
#define T_IP              1
#define T_NAME            2
#define T_PAGE            3
#define T_PLATFORM        4
#define	T_DATE_DDMMMYY    5
#define	T_DATE_YYYY_MM_DD 6
#define T_TIME_HHMMSS     7
#define T_RETURN          8
#define T_BYTES           9
#define T_NUM             10
#define T_GETPOST         11

struct TokenDef {
  TokenDef(char t, std::string p)	{type=t; pattern=p;}
  char          type;
  std::string   pattern;
};
typedef std::vector<TokenDef>  defList;

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
  bool ok; 		
  std::string reason;
  Vec4F vec;
  LogInfo li;
  char ret;

  bool debug_parse = getB(CONF_DEBUGPARSE);

  FILE* fp = fopen (filename.c_str(), "r" );
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
  // std::string format = "* Started {GET} \"{PAGE}\" for {X.X.X.X} at {YYYY-MM-DD} {HH:MM:SS}";
  std::string format = getStr( CONF_FORMAT );
  std::string regexPattern = FormatToRegex ( format, groupLabels );


  while (!feof(fp) && hits < maxlog ) {

    // read next line
    fgets ( m_buf, 65535, fp );
    lin = m_buf;

    // report percentage complete
    size = ftell(fp)/1000;
    perc = (size*100)/max_size; 
    if ( (perc % 5)==0 && perc != percl) {
      percl = perc;
      printf ( " %ld%%. %ld read, %ld skipped.\n", perc, hits, skipped );
      if (skipped > hits && hits==0) {
        printf ("*** ERROR: Log not read. Likely a format issue.\n");
        printf ("Be sure that the format string in your .conf matches the log input.\n");
        printf ("See logrip instructions. You can also set debugparse=1 to test format strings.\n");
        printf ("STOPPED.\n");
        exit(-7);
      }
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

  dbgprintf ( "  Start date: %s\n", m_date_min.WriteDateTime().c_str() );
  dbgprintf ( "  End date:   %s\n", m_date_max.WriteDateTime().c_str() );
  dbgprintf ( "  Total days: %d\n", m_total_days );
  
  TimeX curr_day = m_date_min;		// first day of data	

  // prepare memory for days
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

  int score = 0;

  if (f->lev == SUB_B && f->ip_cnt < getI(CONF_MIN_IPB)) return;
  if (f->lev == SUB_C && f->ip_cnt < getI(CONF_MIN_IPC)) return;
  
  if (f->lev == SUB_C && f->ip_cnt > getI(CONF_MAX_IPC)) score = 6;
  if (f->num_robots > getI(CONF_MAX_ROBOT) )        score = 5;
  if (f->daily_max_hit > getI(CONF_MAX_DAILY_HITS)) score = 4;
  if (f->daily_max_range > getI(CONF_MAX_DAILY_RANGE)) score = 3;
  if (f->max_consecutive >= getI(CONF_MAX_CONSEC_DAYS) && f->daily_max_range > getI(CONF_MAX_CONSEC_RANGE) ) score = 2;
  if (f->daily_ave_hit > getI(CONF_MAX_DAILY_AVE) && f->daily_max_ppm > getF(CONF_MAX_DAILY_PPM)) score = 1;

  bool reasons = getB(CONF_REASONS);
  if (reasons && score > 0 ) {    
    std::string whystr="";
    switch (score) {
    case 6: whystr = "#mach"; break;
    case 5: whystr = "robots"; break;
    case 4: whystr = "daily hits"; break;
    case 3: whystr = "daily range"; break;
    case 2: whystr = "consecutive"; break;
    case 1: whystr = "too fast"; break;
    };
    if (f->lev==SUB_B) whystr += " B-subnet";
    if (f->lev==SUB_C) whystr += " C-subnet";
    printf ( "  IP: %s, Reason: %s\n", ipToStr(f->ip).c_str(), whystr.c_str() );      // print cause of blocking
  }
  
  f->score = score;
  
  f->block = 0;  // blocking action is not computed here
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
        curr_day = f->pages[n].date;      // goto next day
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
    
    // compute the page time deltas (frequency)
    float d;
    diffs.clear ();
    for (int i = 1; i < f->pages.size(); i++) {
      d = f->pages[i].date.GetElapsedSec(f->pages[i-1].date);
      diffs.push_back ( d );
    }

    // get median (ignore outliers and time gaps)
    f->visit_freq = (diffs.size()==0) ? 0 : diffs[ diffs.size()/2 ];        // median
    f->visit_time = f->end_date.GetElapsedSec(f->start_date) / f->page_cnt; // est. visit time
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
  FILE* outcsv;	
  outcsv = fopen(filename.c_str(), "wt");
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
  fprintf ( outcsv, "firstdate, %s\n", m_Log[first].date.WriteDateTime().c_str() );
    
  for (int n = 0; n < m_Log.size(); n++) {
    
    LogInfo& i = m_Log[n];
  
    float tm = i.date.GetDays() - first_tm;
    Vec4F ipvec = ipToVec(i.ip);
    float ip = ipvec.x*256 + ipvec.y + (ipvec.z/256.0f);

    fprintf ( outcsv, "%f, %f\n", tm, ip);
  }

  fclose(outcsv);
}

void LogRip::OutputStats(std::string filename, std::string imgname)
{
  FILE* outcsv;
  LogInfo* i;
  Vec3I actions;

  outcsv = fopen(filename.c_str(), "wt");
  if (outcsv == 0x0) {
    dbgprintf("ERROR: Unable to open %s for writing.\n", filename.c_str());
    exit(-1);
  }
  
  // re-use day structure for stats
  for (int d = 0; d < m_total_days; d++) {
    m_DayList[d].stats.Set(0,0,0);
  }
  
  // insert every hit into day histogram
  // - do not assume log is in time order
  for (int n = 0; n < m_Log.size(); n++) {

    LogInfo& i = m_Log[n];    

    // determine actions taken
    actions.Set(1, i.block != 0, i.block == 0);

    // find and set day accordingly
    int day = i.date.GetElapsedDays (m_date_min);
    m_DayList[day].stats += actions;
  }


  int x1, x2, y1, y2;
  Vec3F y;
  int xr = m_img[0].GetWidth() - 1;
  int yr = m_img[0].GetHeight() - 1;  
  m_img[I_ORIG].Fill(255, 255, 255, 255);

  // find total maximum (for plotting)
  int ymax = 0;
  for (int d = 0; d < m_total_days; d++) {
    if (m_DayList[d].stats.x > ymax) ymax = m_DayList[d].stats.x;
  }
  // round up to nearest base-10 power
  int power = (int) pow(10, (int)log10(ymax));
  ymax = ((ymax + power - 1) / power) * power;  
  if (ymax==0) ymax = 1;
  for (int y = 0; y < ymax; y += ymax / 10) {
    m_img[I_ORIG].Line (0, y*yr/ymax, xr, y*yr/ymax, Vec4F(100,100,100,1));
  }
  // output stats by day and visualize
  std::string datestr;
  float reduced;
  fprintf(outcsv, "Date, All, Blocked, Allowed, Reduction\n");
  for (int d = 0; d < m_total_days; d++) {
    actions = m_DayList[d].stats;
    reduced = float(actions.y)*100.0 / float(actions.x); 
    datestr = m_DayList[d].date.WriteDateTime();    
    printf ( " %s: All hits: %d, Blocked: %d, Allowed: %d, Reduction: %f%%\n", datestr.c_str(), actions.x, actions.y, actions.z, reduced);  
    fprintf( outcsv, "%s, %d, %d, %d, %f\n", datestr.c_str(), actions.x, actions.y, actions.z, reduced );

    x1 = float(d) * xr / m_total_days;
    x2 = float(d+1)*xr / m_total_days;  
    y1 = actions.x * yr / ymax;
    y2 = actions.z * yr / ymax;    
    for (int x=x1; x<x2; x++) {
      m_img[I_ORIG].Line ( x, yr, x, yr-y1, Vec4F(255, 0, 0, 1));
      m_img[I_ORIG].Line ( x, yr, x, yr-y2, Vec4F(0, 255, 0, 1));
    }
  }
  printf ( " out_stats: %d days (x-axis), %d hits (y-axis)\n", m_total_days, ymax );

  m_img[I_ORIG].Save ( imgname.c_str() );

  fclose (outcsv);
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
  FILE* fp;	
  fp = fopen(filename.c_str(), "wt");
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
    if (f->block == 'B') fprintf (fp, "%s/16\n", ipToStr(f->ip, '0').c_str());
  }

  // Class C Blocking
  list =  &m_IPList[ SUB_C ];
  for (it = list->begin(); it != list->end(); it++) {
    f = &it->second;
    if (f->block =='C') fprintf (fp, "%s/24\n", ipToStr(f->ip, '0').c_str() );
  }

  // IP-Level Blocking
  list =  &m_IPList[ SUB_D ];
  for (it = list->begin(); it != list->end(); it++) {
    f = &it->second;	
    if (f->block =='I') fprintf (fp, "%s\n", ipToStr(f->ip, '0').c_str() );
  }

  fclose(fp);
}

void LogRip::OutputVis ()
{
  int xr = m_img[0].GetWidth();
  int yr = m_img[0].GetHeight();	

  // zoom range for vis
  // x = left =   starting day
  // y = bottom = starting A-subnet IP
  // z = right =  ending day
  // w = top =    ending A-subnet IP 
  // default: 0, 0, 1000, 224
  Vec4F range = getV4 ( CONF_VIS_ZOOM );

  if (range.x < 0 ) range.x = 0;
  if (range.z >= m_total_days) range.z = m_total_days-1;
  if (range.w > 224) range.w = 224;

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
  for (int d = 0; d <= m_total_days; d++) {		
    x = (d-range.x)/(range.z+1-range.x) * xr;
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
    x = (tm-range.x)*xr/(range.z+1-range.x);                   // x-axis = time
    y = yr - (ip-range.y*256)*yr/((range.w-range.y)*256);	   // y-axis = ip

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
  pal[0].Set(120, 120, 120, 255); // no blocking - grey
  pal[1].Set(120,120,255,255);    // B net - blue
  pal[2].Set(160,0,160,255);      // C net - purple 
  pal[3].Set(0,255, 0, 255);      // all blocking - green
  float load[7];
  for (int k = 0; k < 4; k++) {
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
  float load_duration = getF(CONF_LOAD_DURATION);   // in seconds
  float vert_scale = getF(CONF_LOAD_SCALE);
  
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
        // increase load from this event
        for (int k=0; k < 4; k++) y[k]++;		
        // reduce load due to blocking	
        if (b > 0 ) {
          if (b=='B') {y[1]--; y[2]--; y[3]--;}
          if (b=='C') {y[2]--; y[3]--;}
          if (b=='I') {y[3]--;}
        }
      }
    }	
    
    // accumulated load (all events)
    for (int k = 0; k <= 4; k++) {
      load[k] += y[k];					
    }		

    // plot loads
    for (int k = 0; k <= 4; k++) {
      y[k] = (yr-1) - y[k] * vert_scale;
      m_img[I_ORIG].Line (x, yr, x, y[k], pal[k] );
      yl[k] = y[k];
    }	
    xl = x;
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

int LogRip::OutputIPs(int outlev, int lev, uint32_t parent, FILE* fp)
{
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

      snprintf(m_buf, 2048, "%s, %d, %d, %d, %.2f, %.2f, %d, %d, %f, %f, %f, %f, %f, %f, %s, %s, %s, %s\n",
        ipstr.c_str(), f->ip_cnt, f->page_cnt, f->uniq_cnt,
        uniq_ratio, f->elapsed,
        f->max_consecutive, f->num_robots,
        f->daily_min_hit, f->daily_min_range/60.0, f->daily_min_ppm, f->daily_max_hit, f->daily_max_range/60.0, f->daily_max_ppm,
        f->lookup[L_ORG].c_str(), f->lookup[L_REGION].c_str(), f->lookup[L_COUNTRY].c_str(), pagename );
            
      if (fp) fwrite(m_buf, 1, strlen(m_buf), fp);

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
  if (outcsv != 0x0) {
    fprintf(outcsv, "IP, ip_cnt, page_cnt, uniq_cnt, uniq_ratio, elapsed(days), max_consec, num_robot, min_hit, min_hr, min_ppm, max_hit, max_hr, max_ppm, org, region, country, page\n" );
  }

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
  if (outcsv != 0x0) fprintf(outcsv, "IP, pages, cnt, page\n");

  IPMap_iter it;
  IPMap_t& list = m_IPList[SUB_D];

  for (it = list.begin(); it != list.end(); it++) {

    IPInfo& f = it->second;

    // sort pages by name 
    SortPagesByName(f.pages);

    if (outcsv != 0x0) fprintf(outcsv, "%s, %d,,\n", ipToStr(it->first).c_str(), f.page_cnt);

    // list unique pages
    int cnt = 1;
    for (int n = 1; n < f.pages.size(); n++) {
      if (f.pages[n].page == f.pages[n - 1].page) {
        cnt++;
      } else {				
        if (outcsv != 0x0) fprintf(outcsv, ",,%d,%s\n", cnt, f.pages[n - 1].page.c_str());
        cnt = 1;
      }	
    }
  }
  fclose ( outcsv );
}


void LogRip::on_arg(int i, std::string arg, std::string val)
{
  if (i > 0) {
    if (arg.find(".txt") != std::string::npos || arg.find(".log") != std::string::npos) {
      m_log_file = arg;
    }
    if (arg.find(".conf") != std::string::npos) {
      m_conf_file = arg;
    }
  }
}

bool LogRip::init()
{
  dbgprintf ("LOGRIP\n");
  dbgprintf ("Copyright (c) 2024-2025, Quanta Sciences, Rama Hoetzlein\n");
  dbgprintf ("Apache 2.0 License\n\n");

  addSearchPath ( ASSET_PATH );
  addSearchPath ( "." );

  m_log_file = "";
  m_conf_file = "";

  return true;
}

// display - called repeatedly after init and on_args
// 
void LogRip::display()
{
  int cnt;

  if (m_log_file.empty() || m_conf_file.empty() ) {
    dbgprintf ( "Usage: logrip {log_file} {config_file}\n\n");
    dbgprintf ("  log_file = .txt or .log access logs from journalctl.\n" );
    dbgprintf ("  conf_file = .conf, config file with format and policy.\n\n");    
    dbgprintf ("ERROR: Must specify both log_file and config_file.\n");
    dbgprintf ("e.g. logrip example.txt ruby.conf\n");
    exit(-1);
  }

  LoadConfig( m_conf_file );

  std::string filename = std::string( m_log_file );
  std::string logfile;
  if (!getFileLocation(filename, logfile)) {
    printf("**** ERROR: Unable to find or open %s\n", filename.c_str());
    exit(-1);
  }

  // load log using dynamic parsing
  LoadLog(logfile);

  // construct IP hash from all page hits
  dbgprintf("Construct IP Hash.\n");
  ConstructIPHash();

  // find start and end date range
  dbgprintf("Preparing Days.\n");
  PrepareDays();

  // sort all IPs and hits by date, compute metrics & scores
  dbgprintf("Processing IPs.\n");
  ProcessIPs(SUB_D);

  // build Class C-subnets by aggregation
  dbgprintf("Constructing C-Subnets.\n");
  ConstructSubnet(SUB_D, SUB_C);

  // build Class B-subnets by aggregation
  dbgprintf("Constructing B-Subnets.\n");
  ConstructSubnet(SUB_C, SUB_B);

  // build Class A-subnets by aggregation
  dbgprintf("Constructing A-Subnets.\n");
  ConstructSubnet(SUB_B, SUB_A);

  // sort all C-subnet IPs and hits by date, compute metrics & score
  dbgprintf("Processing IPs. C-Subnets.\n");
  ProcessIPs(SUB_C);

  // sort all B-subnet IPs and hits by date, compute metrics & score
  dbgprintf("Processing IPs. B-Subnets.\n");
  ProcessIPs(SUB_B);

  // compute blocklist hierarchically for most compact list
  dbgprintf("Computing Blocklist.\n");
  ComputeBlocklist();

  // write out the blocklist
  dbgprintf("Writing Blocklist.\n");
  OutputBlocklist("out_blocklist.txt");

  // write B-subnet list with metrics
  dbgprintf("Writing IPs (B-Subnets)... ");
  cnt = OutputIPs(SUB_B, "out_ips_bnet.csv");
  printf("%d ips.\n", cnt);

  // write C-subnet list with metrics
  dbgprintf("Writing IPs (C-Subnets)... ");
  cnt = OutputIPs(SUB_C, "out_ips_cnet.csv");
  printf("%d ips.\n", cnt);

  // write full IP list with metrics
  dbgprintf("Writing IPs (All Mach)... ");
  cnt = OutputIPs(SUB_D, "out_ips.csv");
  printf("%d ips.\n", cnt);

  // write list of all hits organized by IP
  dbgprintf("Writing Pages.\n");
  OutputPages("out_pages.csv");

  dbgprintf("Writing Hits.\n");
  OutputHits("out_hits.csv");

  // create an image for visualization products  
  Vec4F res = getV4( CONF_VIS_RES );
  CreateImg( res.x, res.y );

  // output visualizations: orginial, blocked, post-filtered
  dbgprintf("Writing Visualizations.\n");
  OutputVis();

  // use day-sorted hits to report stats (/w and w/o blocking)
  dbgprintf("Writing Daily Stats.\n");
  OutputStats("out_stats.csv", "out_stats.png");

  // compute and visualize estimated server load (before & after)
  dbgprintf("Writing Loads.\n");
  OutputLoads("");

  dbgprintf("Done.\n");

  exit(1);
}

void LogRip::startup()
{
  appStart("Logrip (c) 2024-2025, Quanta Sciences", "logrip", 1024, 768, 3, 5, 16 );
}





