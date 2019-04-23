/*
 * Copyright (C) 2019 SensorsAnalytics
 * All rights reserved.
 *
 * https://www.sensorsdata.cn/manual/cpp_sdk.html
 */

#include "sensors_analytics_sdk.h"

#include <curl/curl.h>
#include <zlib.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#else

#include <pthread.h>
#include <sys/time.h>

#endif

namespace sensors_analytics {
namespace utils {

void ObjectNode::SetNumber(const string& property_name, double value) {
  properties_map_[property_name] = ValueNode(value);
}

void ObjectNode::SetNumber(const string& property_name, int32_t value) {
  properties_map_[property_name] = ValueNode(static_cast<int64_t>(value));
}

void ObjectNode::SetNumber(const string& property_name, int64_t value) {
  properties_map_[property_name] = ValueNode(value);
}

static const size_t kStringPropertyValueMaxLength = 8192;

bool CheckUtf8Valid(const string& str) {
  // https://stackoverflow.com/questions/1031645/how-to-detect-utf-8-in-plain-c/1031683#1031683 Christoph
  const unsigned char* bytes = (const unsigned char*) str.data();
  const unsigned char* begin = bytes;
  while (bytes - begin < str.length()) {
    if ((bytes[0] == 0x09 || bytes[0] == 0x0A || bytes[0] == 0x0D || (0x20 <= bytes[0] && bytes[0] <= 0x7E))) {
      bytes += 1;
      continue;
    }
    if (((0xC2 <= bytes[0] && bytes[0] <= 0xDF) && (0x80 <= bytes[1] && bytes[1] <= 0xBF))) {
      bytes += 2;
      continue;
    }
    if ((bytes[0] == 0xE0 && (0xA0 <= bytes[1] && bytes[1] <= 0xBF) && (0x80 <= bytes[2] && bytes[2] <= 0xBF)) ||
        (((0xE1 <= bytes[0] && bytes[0] <= 0xEC) || bytes[0] == 0xEE || bytes[0] == 0xEF) &&
         (0x80 <= bytes[1] && bytes[1] <= 0xBF) && (0x80 <= bytes[2] && bytes[2] <= 0xBF)) ||
        (bytes[0] == 0xED && (0x80 <= bytes[1] && bytes[1] <= 0x9F) && (0x80 <= bytes[2] && bytes[2] <= 0xBF))) {
      bytes += 3;
      continue;
    }
    if ((bytes[0] == 0xF0 && (0x90 <= bytes[1] && bytes[1] <= 0xBF) && (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
         (0x80 <= bytes[3] && bytes[3] <= 0xBF)) ||
        ((0xF1 <= bytes[0] && bytes[0] <= 0xF3) && (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
         (0x80 <= bytes[2] && bytes[2] <= 0xBF) && (0x80 <= bytes[3] && bytes[3] <= 0xBF)) ||
        (bytes[0] == 0xF4 && (0x80 <= bytes[1] && bytes[1] <= 0x8F) && (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
         (0x80 <= bytes[3] && bytes[3] <= 0xBF))) {
      bytes += 4;
      continue;
    }
    return false;
  }
  return bytes - begin == str.length();
}

void ObjectNode::SetString(const string& property_name, const string& value) {
  if (value.length() > kStringPropertyValueMaxLength) {
    std::cerr << "String property '" << property_name << "' is too long, value: " << value << std::endl;
    return;
  }
  if (!CheckUtf8Valid(value)) {
    std::cerr << "String property '" << property_name << "' is not valid UTF-8 string, value: " << value << std::endl;
    return;
  }
  properties_map_[property_name] = ValueNode(value);
}

void ObjectNode::SetString(const string& property_name, const char* value) {
  SetString(property_name, string(value));
}

void ObjectNode::SetBool(const string& property_name, bool value) {
  properties_map_[property_name] = ValueNode(value);
}

void ObjectNode::SetObject(const string& property_name, const ObjectNode& value) {
  properties_map_[property_name] = ValueNode(value);
}

void ObjectNode::SetList(const string& property_name, const std::vector<string>& value) {
  properties_map_[property_name] = ValueNode(value);
}

void ObjectNode::SetDateTime(const string& property_name, const time_t seconds, int milliseconds) {
  properties_map_[property_name] = ValueNode(seconds, milliseconds);
}

void utils::ObjectNode::SetDateTime(const string& property_name, const string& value) {
  properties_map_[property_name] = ValueNode(value);
}

void ObjectNode::Clear() {
  properties_map_.clear();
}

void ObjectNode::DumpNode(const ObjectNode& node, string* buffer) {
  *buffer += '{';
  bool first = true;

  for (std::map<string, ValueNode>::const_iterator iterator = node.properties_map_.begin();
       iterator != node.properties_map_.end(); ++iterator) {
    if (first) {
      first = false;
    } else {
      *buffer += ',';
    }
    *buffer += '"' + iterator->first + "\":";
    ValueNode::ToStr(iterator->second, buffer);
  }
  *buffer += '}';
}

void ObjectNode::ValueNode::DumpString(const string& value, string* buffer) {
  *buffer += '"';
  for (std::string::size_type i = 0; i < value.length(); ++i) {
    char c = value[i];
    switch (c) {
      case '"':
        *buffer += "\\\"";
        break;
      case '\\':
        *buffer += "\\\\";
        break;
      case '\b':
        *buffer += "\\b";
        break;
      case '\f':
        *buffer += "\\f";
        break;
      case '\n':
        *buffer += "\\n";
        break;
      case '\r':
        *buffer += "\\r";
        break;
      case '\t':
        *buffer += "\\t";
        break;
      default:
        *buffer += c;
        break;
    }
  }
  *buffer += '"';
}

void ObjectNode::ValueNode::DumpList(const std::vector<string>& value, string* buffer) {
  *buffer += '[';
  bool first = true;
  for (std::vector<string>::const_iterator iterator = value.begin(); iterator != value.end(); ++iterator) {
    if (first) {
      first = false;
    } else {
      *buffer += ',';
    }
    DumpString(*iterator, buffer);
  }
  *buffer += ']';
}

#if defined(__linux__)
#define SA_SDK_LOCALTIME(seconds, now) localtime_r((seconds), (now))
#elif defined(__APPLE__)
#define SA_SDK_LOCALTIME(seconds, now) localtime_r((seconds), (now))
#elif defined(_WIN32)
#define SA_SDK_LOCALTIME(seconds, now) localtime_s((now), (seconds))
#define snprintf sprintf_s
#endif

void ObjectNode::ValueNode::DumpDateTime(const time_t& seconds, int milliseconds, string* buffer) {
  struct tm tm = {};
  SA_SDK_LOCALTIME(&seconds, &tm);
  char buff[64];
  snprintf(buff, sizeof(buff), "\"%04d-%02d-%02d %02d:%02d:%02d.%03d\"",
           tm.tm_year + 1900,
           tm.tm_mon + 1,
           tm.tm_mday,
           tm.tm_hour,
           tm.tm_min,
           tm.tm_sec,
           milliseconds);
  *buffer += buff;
}

string ObjectNode::ToJson(const ObjectNode& node) {
  string buffer;
  DumpNode(node, &buffer);
  return buffer;
}

void ObjectNode::MergeFrom(const utils::ObjectNode& another_node) {
  for (std::map<string, ValueNode>::const_iterator iterator = another_node.properties_map_.begin();
       iterator != another_node.properties_map_.end(); ++iterator) {
    properties_map_[iterator->first] = iterator->second;
  }
}

ObjectNode::ObjectNode() {}

utils::ObjectNode::ValueNode::ValueNode(double value) : node_type_(NUMBER) {
  value_.number_value = value;
}

utils::ObjectNode::ValueNode::ValueNode(int64_t value) : node_type_(INT) {
  value_.int_value = value;
}

utils::ObjectNode::ValueNode::ValueNode(const string& value) : node_type_(STRING),
                                                               string_data_(value) {}

utils::ObjectNode::ValueNode::ValueNode(bool value) : node_type_(BOOL) {
  value_.bool_value = value;
}

utils::ObjectNode::ValueNode::ValueNode(const utils::ObjectNode& value) : node_type_(OBJECT) {
  object_data_ = value;
}

utils::ObjectNode::ValueNode::ValueNode(const std::vector<string>& value) : node_type_(LIST),
                                                                            list_data_(value) {}

utils::ObjectNode::ValueNode::ValueNode(time_t seconds, int milliseconds) : node_type_(DATETIME) {
  value_.date_time_value.seconds = seconds;
  value_.date_time_value.milliseconds = milliseconds;
}

void utils::ObjectNode::ValueNode::ToStr(const utils::ObjectNode::ValueNode& node, string* buffer) {
  switch (node.node_type_) {
    case NUMBER:
      DumpNumber(node.value_.number_value, buffer);
      break;
    case INT:
      DumpNumber(node.value_.int_value, buffer);
      break;
    case STRING:
      DumpString(node.string_data_, buffer);
      break;
    case LIST:
      DumpList(node.list_data_, buffer);
      break;
    case BOOL:
      *buffer += (node.value_.bool_value ? "true" : "false");
      break;
    case OBJECT:
      DumpNode(node.object_data_, buffer);
      break;
    case DATETIME:
      DumpDateTime(node.value_.date_time_value.seconds,
                   node.value_.date_time_value.milliseconds, buffer);
      break;
    default:
      break;
  }
}

void ObjectNode::ValueNode::DumpNumber(double value, string* buffer) {
  std::ostringstream buf;
  buf << value;
  *buffer += buf.str();
}

void ObjectNode::ValueNode::DumpNumber(int64_t value, string* buffer) {
  std::ostringstream buf;
  buf << value;
  *buffer += buf.str();
}

namespace rest_client {

typedef std::map<std::string, std::string> HeaderFields;

typedef struct {
  int code_;
  std::string body_;
  HeaderFields headers_;
} Response;

class Connection {
 public:
  typedef struct {
    double total_time_;
    double name_lookup_time_;
    double connect_time_;
    double app_connect_time_;
    double pre_transfer_time_;
    double start_transfer_time_;
    double redirect_time_;
    int redirect_count_;
  } RequestInfo;

  explicit Connection(const std::string& base_url);

  ~Connection();

  void SetTimeout(int seconds);

  void AppendHeader(const std::string& key, const std::string& value);

  Response Post(const std::string& url, const std::string& data);

 private:
  Response PerformCurlRequest(const std::string& uri);

  CURL* curl_handle_;
  std::string base_url_;
  HeaderFields header_fields_;
  int timeout_;
  bool follow_redirects_;
  int max_redirects_;
  bool no_signal_;
  RequestInfo last_request_;
};

Response Post(const std::string& url,
              const std::string& ctype,
              const std::string& data,
              int timeout_second,
              const std::vector<std::pair<string, string> >& headers
              = std::vector<std::pair<string, string> >());

namespace helpers {
size_t WriteCallback(void* data, size_t size, size_t nmemb, void* user_data);

size_t HeaderCallback(void* data, size_t size, size_t nmemb, void* user_data);

inline std::string& TrimLeft(std::string& s);  // NOLINT
inline std::string& TrimRight(std::string& s);  // NOLINT
inline std::string& Trim(std::string& s);  // NOLINT
}  // namespace helpers

Connection::Connection(const std::string& base_url)
  : last_request_(), header_fields_() {
  this->curl_handle_ = curl_easy_init();
  if (!this->curl_handle_) {
    throw std::runtime_error("Couldn't initialize curl handle");
  }
  this->base_url_ = base_url;
  this->timeout_ = 0;
  this->follow_redirects_ = false;
  this->max_redirects_ = -1l;
  this->no_signal_ = false;
}

Connection::~Connection() {
  if (this->curl_handle_) {
    curl_easy_cleanup(this->curl_handle_);
  }
}

void Connection::AppendHeader(const std::string& key, const std::string& value) {
  this->header_fields_[key] = value;
}

void Connection::SetTimeout(int seconds) {
  this->timeout_ = seconds;
}

/**
 * @brief helper function to get called from the actual request methods to
 * prepare the curlHandle for transfer with generic options, perform the
 * request and record some stats from the last request and then reset the
 * handle with curl_easy_reset to its default state. This will keep things
 * like connections and session ID intact but makes sure you can change
 * parameters on the object for another request.
 *
 * @param uri URI to query
 * @param ret Reference to the Response struct that should be filled
 *
 * @return 0 on success and 1 on error
 */
Response Connection::PerformCurlRequest(const std::string& uri) {
  // init return type
  Response ret = {};

  std::string url = std::string(this->base_url_ + uri);
  std::string header_string;
  CURLcode res;
  curl_slist* header_list = NULL;

  /** set query URL */
  curl_easy_setopt(this->curl_handle_, CURLOPT_URL, url.c_str());
  /** set callback function */
  curl_easy_setopt(this->curl_handle_, CURLOPT_WRITEFUNCTION,
                   helpers::WriteCallback);
  /** set data object to pass to callback function */
  curl_easy_setopt(this->curl_handle_, CURLOPT_WRITEDATA, &ret);
  /** set the header callback function */
  curl_easy_setopt(this->curl_handle_, CURLOPT_HEADERFUNCTION,
                   helpers::HeaderCallback);
  /** callback object for headers */
  curl_easy_setopt(this->curl_handle_, CURLOPT_HEADERDATA, &ret);
  /** set http headers */
  for (HeaderFields::const_iterator it = this->header_fields_.begin();
       it != this->header_fields_.end(); ++it) {
    header_string = it->first;
    header_string += ": ";
    header_string += it->second;
    header_list = curl_slist_append(header_list, header_string.c_str());
  }
  curl_easy_setopt(this->curl_handle_, CURLOPT_HTTPHEADER,
                   header_list);
  /** set user agent */
  curl_easy_setopt(this->curl_handle_, CURLOPT_USERAGENT,
                   SA_SDK_FULL_NAME);

  // 若使用 HTTPS，有两种配置方式，选用其中一种即可：
  // 1. 使用 CA 证书（下载地址 http://curl.haxx.se/ca/cacert.pem ），去掉下面一行的注释，并指定证书路径，例如证书在当前目录下
  // curl_easy_setopt(this->curl_handle_, CURLOPT_CAINFO, "cacert.pem");
  // 2. （不建议，仅测试时方便可以使用）不验证服务端证书，去掉下面两行的注释
  // curl_easy_setopt(this->curl_handle_, CURLOPT_SSL_VERIFYHOST, 0L);
  // curl_easy_setopt(this->curl_handle_, CURLOPT_SSL_VERIFYPEER, 0L);

  // set timeout
  if (this->timeout_) {
    curl_easy_setopt(this->curl_handle_, CURLOPT_TIMEOUT, this->timeout_);
    // dont want to get a sig alarm on timeout
    curl_easy_setopt(this->curl_handle_, CURLOPT_NOSIGNAL, 1);
  }
  // set follow redirect
  if (this->follow_redirects_) {
    curl_easy_setopt(this->curl_handle_, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(this->curl_handle_, CURLOPT_MAXREDIRS,
                     static_cast<int64_t>(this->max_redirects_));
  }

  if (this->no_signal_) {
    // multi-threaded and prevent entering foreign signal handler (e.g. JNI)
    curl_easy_setopt(this->curl_handle_, CURLOPT_NOSIGNAL, 1);
  }

  res = curl_easy_perform(this->curl_handle_);
  if (res != CURLE_OK) {
    ret.body_ = curl_easy_strerror(res);
    ret.code_ = -1;
  } else {
    int64_t http_code = 0;
    curl_easy_getinfo(this->curl_handle_, CURLINFO_RESPONSE_CODE, &http_code);
    ret.code_ = static_cast<int>(http_code);
  }

  curl_easy_getinfo(this->curl_handle_, CURLINFO_TOTAL_TIME,
                    &this->last_request_.total_time_);
  curl_easy_getinfo(this->curl_handle_, CURLINFO_NAMELOOKUP_TIME,
                    &this->last_request_.name_lookup_time_);
  curl_easy_getinfo(this->curl_handle_, CURLINFO_CONNECT_TIME,
                    &this->last_request_.connect_time_);
  curl_easy_getinfo(this->curl_handle_, CURLINFO_APPCONNECT_TIME,
                    &this->last_request_.app_connect_time_);
  curl_easy_getinfo(this->curl_handle_, CURLINFO_PRETRANSFER_TIME,
                    &this->last_request_.pre_transfer_time_);
  curl_easy_getinfo(this->curl_handle_, CURLINFO_STARTTRANSFER_TIME,
                    &this->last_request_.start_transfer_time_);
  curl_easy_getinfo(this->curl_handle_, CURLINFO_REDIRECT_TIME,
                    &this->last_request_.redirect_time_);
  curl_easy_getinfo(this->curl_handle_, CURLINFO_REDIRECT_COUNT,
                    &this->last_request_.redirect_count_);
  // free header list
  curl_slist_free_all(header_list);
  // reset curl handle
  curl_easy_reset(this->curl_handle_);
  return ret;
}

Response Connection::Post(const std::string& url, const std::string& data) {
  /** Now specify we want to POST data */
  curl_easy_setopt(this->curl_handle_, CURLOPT_POST, 1L);
  /** set post fields */
  curl_easy_setopt(this->curl_handle_, CURLOPT_POSTFIELDS, data.c_str());
  curl_easy_setopt(this->curl_handle_, CURLOPT_POSTFIELDSIZE, data.size());

  return this->PerformCurlRequest(url);
}

size_t helpers::WriteCallback(void* data, size_t size, size_t nmemb, void* user_data) {
  Response* r;
  r = reinterpret_cast<Response*>(user_data);
  r->body_.append(reinterpret_cast<char*>(data), size * nmemb);

  return (size * nmemb);
}

/**
 * @brief header callback for libcurl
 *
 * @param data returned (header line)
 * @param size of data
 * @param nmemb memblock
 * @param user_data pointer to user data object to save headr data
 * @return size * nmemb;
 */
size_t helpers::HeaderCallback(void* data, size_t size, size_t nmemb, void* user_data) {
  Response* r;
  r = reinterpret_cast<Response*>(user_data);
  std::string header(reinterpret_cast<char*>(data), size * nmemb);
  size_t separator = header.find_first_of(':');
  if (std::string::npos == separator) {
    // roll with non seperated headers...
    Trim(header);
    if (0 == header.length()) {
      return (size * nmemb);  // blank line;
    }
    r->headers_[header] = "present";
  } else {
    std::string key = header.substr(0, separator);
    Trim(key);
    std::string value = header.substr(separator + 1);
    Trim(value);
    r->headers_[key] = value;
  }

  return (size * nmemb);
}

inline std::string& helpers::TrimLeft(std::string& s) {  // NOLINT
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
  return s;
}

inline std::string& helpers::TrimRight(std::string& s) { // NOLINT
  s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
  return s;
}

inline std::string& helpers::Trim(std::string& s) {  // NOLINT
  return TrimLeft(TrimRight(s));
}

Response Post(const std::string& url,
              const std::string& ctype,
              const std::string& data,
              int timeout_second,
              const std::vector<std::pair<string, string> >& headers) {
  Response ret;
  Connection* conn;
  try {
    conn = new Connection("");
  } catch (std::runtime_error& e) {
    std::cerr << e.what() << std::endl;
    Response response;
    response.code_ = -1;
    response.body_ = e.what();
    return response;
  }

  conn->SetTimeout(timeout_second);
  if (ctype.length() > 0) {
    conn->AppendHeader("Content-Type", ctype);
  }
  for (std::vector<std::pair<string, string> >::const_iterator iterator = headers.begin();
       iterator != headers.end(); ++iterator) {
    conn->AppendHeader(iterator->first, iterator->second);
  }
  ret = conn->Post(url, data);
  delete conn;
  return ret;
}
}  // namespace rest_client
}  // namespace utils

class HttpSender {
 public:
  explicit HttpSender(const string& server_url,
                      const std::vector<std::pair<string, std::string> >& http_headers
                      = std::vector<std::pair<string, std::string> >());

  bool Send(const string& data);

 private:
  static bool CompressString(const string& str, string* out_string, int compression_level);

  static bool EncodeToRequestBody(const string& data, string* request_body);

  static string Base64Encode(const string& data);

  static string UrlEncode(const string& data);

  friend class Sdk;
  static const int kRequestTimeoutSecond = 3;
  string server_url_;
  std::vector<std::pair<string, std::string> > http_headers_;
};

HttpSender::HttpSender(const string& server_url, const std::vector<std::pair<string, string> >& http_headers) :
  server_url_(server_url), http_headers_(http_headers) {}

bool HttpSender::Send(const string& data) {
  string request_body;
  if (!EncodeToRequestBody(data, &request_body)) {
    return false;
  }
  utils::rest_client::Response
    response = utils::rest_client::Post(server_url_, "", request_body, kRequestTimeoutSecond);
  if (response.code_ != 200) {
    std::cerr << "SensorsAnalytics SDK send failed: " << response.body_ << std::endl;
    return false;
  }
  return true;
}

bool HttpSender::CompressString(const string& str, string* out_string, int compression_level = Z_BEST_COMPRESSION) {
  z_stream zs;  // z_stream is zlib's control structure
  memset(&zs, 0, sizeof(zs));

  if (deflateInit2(&zs, compression_level, Z_DEFLATED,
                   15 | 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
    std::cerr << "deflateInit2 failed while compressing." << std::endl;
    return false;
  }

  zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(str.data()));
  zs.avail_in = static_cast<uInt>(str.size());  // set the z_stream's input

  int ret;
  char out_buffer[32768];

  // retrieve the compressed bytes blockwise
  do {
    zs.next_out = reinterpret_cast<Bytef*>(out_buffer);
    zs.avail_out = sizeof(out_buffer);

    ret = deflate(&zs, Z_FINISH);

    if (out_string->size() < zs.total_out) {
      // append the block to the output string
      out_string->append(out_buffer, zs.total_out - out_string->size());
    }
  } while (ret == Z_OK);

  deflateEnd(&zs);

  if (ret != Z_STREAM_END) {  // an error occurred that was not EOF
    std::cerr << "Exception during zlib compression: (" << ret << ") " << zs.msg << std::endl;
    return false;
  }

  return true;
}

static const char kBase64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string HttpSender::Base64Encode(const string& data) {
  const unsigned char* bytes_to_encode = reinterpret_cast<const unsigned char*>(data.data());
  size_t in_len = data.length();
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len-- > 0) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for (i = 0; (i < 4); i++)
        ret += kBase64Chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i != 0) {
    for (j = i; j < 3; j++)
      char_array_3[j] = '\0';
    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;
    for (j = 0; (j < i + 1); j++)
      ret += kBase64Chars[char_array_4[j]];
    while ((i++ < 3))
      ret += '=';
  }
  return ret;
}

string HttpSender::UrlEncode(const string& data) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;

  for (std::string::size_type i = 0; i < data.size(); ++i) {
    char c = data[i];
    // Keep alphanumeric and other accepted characters intact
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      escaped << c;
      continue;
    }

    // Any other characters are percent-encoded
    escaped << std::uppercase;
    escaped << '%' << std::setw(2) << int((unsigned char) c);
    escaped << std::nouppercase;
  }

  return escaped.str();
}

bool HttpSender::EncodeToRequestBody(const string& data, string* request_body) {
  string compressed_data;
  if (!CompressString(data, &compressed_data)) {
    return false;
  }
  const string base64_encoded_data = Base64Encode(compressed_data);
  *request_body = "data_list=" + UrlEncode(base64_encoded_data) + "&gzip=1";
  return true;
}

void PropertiesNode::SetObject(const string& property_name, const utils::ObjectNode& value) {}

class DefaultConsumer {
 public:
  DefaultConsumer(const string& server_url, const string& data_file_path, int max_staging_record_count);

  void Init();

  void Send(const utils::ObjectNode& record);

  // 触发一次发送
  // 发送最多 kFlushAllBatchSize(30) 条数据
  // 当 drop_failed_record 为 true 时，发送失败则丢弃这些数据不再发送
  // 当 drop_failed_record 为 false 时，发送失败仍保留在队列里，下次再试
  bool FlushPart(size_t part_size, bool drop_failed_record);

  // 发送当前所有数据，如果发送中断（失败）返回 false，全部发送成功返回 true
  bool Flush();

  // 清空发送队列，包括磁盘文件
  void Clear();

  ~DefaultConsumer();

 private:
  // 清空文件内容
  void TruncateStagingFile();

  // 将文件里的数据添加到内存的队列里，直到队列满，并清空磁盘文件
  void LoadRecordFromDisk();

  // 将内存队列写到磁盘，供以后读取
  void DumpRecordToDisk();

  // 关闭 Consumer 时，将内存里数据与本地合并写到暂存文件
  void Close();

  static const size_t kFlushAllBatchSize = 30;

#if defined(_WIN32)
#define SA_MUTEX CRITICAL_SECTION
#define SA_MUTEX_LOCK(mutex) EnterCriticalSection((mutex))
#define SA_MUTEX_UNLOCK(mutex) LeaveCriticalSection((mutex))
#define SA_MUTEX_INIT(mutex) InitializeCriticalSection((mutex))
#define SA_MUTEX_DESTROY(mutex) DeleteCriticalSection((mutex))
#else
#define SA_MUTEX pthread_mutex_t
#define SA_MUTEX_LOCK(mutex) pthread_mutex_lock((mutex))
#define SA_MUTEX_UNLOCK(mutex) pthread_mutex_unlock((mutex))
#define SA_MUTEX_INIT(mutex) \
do { \
  pthread_mutexattr_t mutex_attr; \
  pthread_mutexattr_init(&mutex_attr); \
  pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE); \
  pthread_mutex_init((mutex), &mutex_attr); \
} while(0)
#define SA_MUTEX_DESTROY(mutex) pthread_mutex_destroy((mutex))
#endif

  SA_MUTEX records_mutex_; // 操作 records_
  SA_MUTEX sending_mutex_; // 发送 FlushPart()

  class LockGuard {
   public:
    LockGuard(SA_MUTEX* mutex) : mutex_(mutex) {
      SA_MUTEX_LOCK(mutex_);
    }

    ~LockGuard() {
      SA_MUTEX_UNLOCK(mutex_);
    }

   private:
    SA_MUTEX* mutex_;
  };

  std::deque<string> records_;
  string data_file_path_;
  int max_staging_record_count_;
  bool need_try_load_from_disk_;
  HttpSender* sender_;
};

DefaultConsumer::DefaultConsumer(const string& server_url, const string& data_file_path, int max_staging_record_count)
  : data_file_path_(data_file_path),
    max_staging_record_count_(max_staging_record_count),
    need_try_load_from_disk_(true),
    sender_(new HttpSender(server_url)) {}

void DefaultConsumer::Send(const utils::ObjectNode& record) {
  const string json_record = utils::ObjectNode::ToJson(record);

  LockGuard records_lock(&records_mutex_);
  records_.push_back(json_record);
  if (records_.size() > (size_t) max_staging_record_count_) {
    records_.pop_front();
  }
}

bool DefaultConsumer::FlushPart(size_t part_size, bool drop_failed_record) {
  // 从本地文件读出之前 dump 到磁盘的数据，补满发送队列
  LoadRecordFromDisk();

  LockGuard sending_lock(&sending_mutex_);
  std::vector<string> sending_records;
  size_t flush_size;
  {
    LockGuard records_lock(&records_mutex_);
    flush_size = part_size < records_.size() ? part_size : records_.size();
    if (flush_size == 0) {
      return true;
    }
    std::deque<string>::iterator iter_end = records_.begin() + flush_size;
    sending_records.assign(records_.begin(), iter_end);
    records_.erase(records_.begin(), iter_end);
  }

  std::stringstream buffer;
  buffer << '[';
  for (std::vector<string>::const_iterator iter = sending_records.begin(); iter != sending_records.end(); ++iter) {
    if (iter != sending_records.begin()) {
      buffer << ',';
    }
    buffer << *iter;
  }
  buffer << ']';
  bool send_result = sender_->Send(buffer.str());

  if (!send_result && !drop_failed_record) {
    // 如果发送失败并且发送失败的不能丢，那么放回发送队列
    {
      LockGuard records_lock(&records_mutex_);
      size_t records_remain_size = max_staging_record_count_ - records_.size();
      if (records_remain_size > 0) {
        // 需要从最前面补满 records_，从 sending_records 的 begin_idx 元素到最后一个元素
        size_t begin_idx = sending_records.size() > records_remain_size ?
                           sending_records.size() - records_remain_size : 0;
        std::vector<string>::iterator copy_sending_begin = sending_records.begin() + begin_idx;
        records_.insert(records_.begin(), copy_sending_begin, sending_records.end());
      }
    }
  }
  return send_result;
}

bool DefaultConsumer::Flush() {
  LoadRecordFromDisk();
  while (true) {
    {
      LockGuard records_lock(&records_mutex_);
      if (records_.empty()) {
        break;
      }
    }

    bool flush_result = FlushPart(kFlushAllBatchSize, false);
    if (!flush_result) {
      return false;
    }
  }
  return true;
}

void DefaultConsumer::Clear() {
  LockGuard records_lock(&records_mutex_);
  records_.clear();
  TruncateStagingFile();
}

DefaultConsumer::~DefaultConsumer() {
  Close();
}

inline void DefaultConsumer::TruncateStagingFile() {
  std::ofstream staging_ofs(data_file_path_.c_str(), std::ofstream::out | std::ofstream::trunc);
  staging_ofs.close();
}

void DefaultConsumer::LoadRecordFromDisk() {
  LockGuard records_lock(&records_mutex_);
  if (!need_try_load_from_disk_) {
    return;
  }
  size_t memory_remain_size = max_staging_record_count_ - records_.size();
  if (memory_remain_size > 0) {
    // 读文件里最后 memory_remain_size 条数据
    std::deque<string> record_buffer;
    std::ifstream staging_ifs(data_file_path_.c_str(), std::ofstream::in);
    string line;
    while (std::getline(staging_ifs, line)) {
      if (line.length() == 0 || line[0] != '{' || line[line.length() - 1] != '}') {
        continue;
      }
      record_buffer.push_back(line);
      if (record_buffer.size() > memory_remain_size) {
        record_buffer.pop_front();
      }
    }
    staging_ifs.close();

    records_.insert(records_.begin(), record_buffer.begin(), record_buffer.end());
  }
  TruncateStagingFile();
  // 标记不需要尝试读磁盘文件
  need_try_load_from_disk_ = false;
}

inline void DefaultConsumer::DumpRecordToDisk() {
  std::ofstream staging_ofs(data_file_path_.c_str(), std::ofstream::out | std::ofstream::trunc);
  for (std::deque<string>::const_iterator iterator = records_.begin(); iterator != records_.end(); ++iterator) {
    staging_ofs << *iterator << std::endl;
  }
  staging_ofs.close();
}

void DefaultConsumer::Init() {
  SA_MUTEX_INIT(&records_mutex_);
  SA_MUTEX_INIT(&sending_mutex_);
}

void DefaultConsumer::Close() {
  LockGuard records_lock(&records_mutex_);
  LoadRecordFromDisk();
  DumpRecordToDisk();
  if (sender_ != NULL) {
    delete sender_;
    sender_ = NULL;
  }
  SA_MUTEX_DESTROY(&sending_mutex_);
  SA_MUTEX_DESTROY(&records_mutex_);
}

Sdk* Sdk::instance_ = NULL;

/// class Sdk
#define RETURN_IF_ERROR(stmt) do { if (!stmt) return false; } while (false)

bool Sdk::Init(const std::string& data_file_path,
               const std::string& server_url,
               const std::string& distinct_id,
               bool is_login_id,
               int max_staging_record_count) {
  RETURN_IF_ERROR(AssertId("Distinct ID", distinct_id));
  if (!instance_) {
    instance_ = new Sdk(server_url, data_file_path, max_staging_record_count, distinct_id, is_login_id);
    instance_->consumer_->Init();
  }
  return true;
}

void Sdk::RegisterSuperProperties(const PropertiesNode& properties) {
  if (instance_) {
    instance_->super_properties_->MergeFrom(properties);
  }
}

void Sdk::ClearSuperProperties() {
  if (instance_) {
    instance_->ResetSuperProperties();
  }
}

bool Sdk::AddEvent(const string& action_type,
                   const string& event_name,
                   const utils::ObjectNode& properties,
                   const string& distinct_id,
                   const string& original_id) {
  RETURN_IF_ERROR(AssertProperties(properties));
  if ("track" == action_type) {
    RETURN_IF_ERROR(AssertKey("Event Name", event_name));
  } else if ("track_signup" == action_type) {
    RETURN_IF_ERROR(AssertId("Original ID", original_id));
  }

  utils::ObjectNode record_properties;
  if (action_type.find("track") != std::string::npos) {
    record_properties.MergeFrom(*super_properties_);
  }
  record_properties.MergeFrom(properties);

  int64_t current_timestamp;
  std::map<string, utils::ObjectNode::ValueNode>::iterator time_property_iter =
    record_properties.properties_map_.find("$time");
  if (time_property_iter != record_properties.properties_map_.end()) {
    current_timestamp = 1000L * time_property_iter->second.value_.date_time_value.seconds +
                        time_property_iter->second.value_.date_time_value.milliseconds;
    record_properties.properties_map_.erase(time_property_iter);
  } else {
#if defined(_WIN32)
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    const int64_t kUnixTimeStart = 0x019DB1DED53E8000L; //January 1, 1970 (start of Unix epoch) in "ticks"
    const int64_t kTicksPerMillisecond = 10000;
    LARGE_INTEGER li;
    li.LowPart  = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    current_timestamp = (li.QuadPart - kUnixTimeStart) / kTicksPerMillisecond;
#else
    struct timeval now;
    gettimeofday(&now, NULL);
    current_timestamp = (long) now.tv_sec * 1000 + (long) (now.tv_usec / 1000);
#endif
  }

  string project;
  std::map<string, utils::ObjectNode::ValueNode>::iterator project_property_iter =
    record_properties.properties_map_.find("$project");
  if (project_property_iter != record_properties.properties_map_.end()) {
    project = project_property_iter->second.string_data_;
    record_properties.properties_map_.erase(project_property_iter);
  }

  if (is_login_id_) {
    record_properties.SetBool("$is_login_id", true);
  }

  utils::ObjectNode lib_node;
  lib_node.SetString("$lib", "cpp");
  lib_node.SetString("$lib_version", SA_SDK_VERSION);
  lib_node.SetString("$lib_method", "code");
  // TODO(fengjiajie): 后面补充埋点详情

  utils::ObjectNode record_node;
  record_node.SetString("type", action_type);
  record_node.SetNumber("time", current_timestamp);
  record_node.SetString("distinct_id", distinct_id);
  record_node.SetObject("properties", record_properties);
  record_node.SetObject("lib", lib_node);

  if (project.length() > 0) {
    record_node.SetString("project", project);
  }

  if ("track" == action_type) {
    record_node.SetString("event", event_name);
  } else if ("track_signup" == action_type) {
    record_node.SetString("event", event_name);
    record_node.SetString("original_id", original_id);
  }

  consumer_->Send(record_node);
  return true;
}

bool Sdk::AssertId(const string& type, const string& key) {
  if (key.length() < 1) {
    std::cerr << "The " << type << " is empty." << std::endl;
    return false;
  } else if (key.length() > 255) {
    std::cerr << "The " << type << " is too long, max length is 255." << std::endl;
    return false;
  }
  return true;
}

bool Sdk::AssertKey(const string& type, const string& key) {
  size_t len = key.length();
  if (len < 1 || len > 100) {
    std::cerr << "The " << type << " is empty or too long, max length is 100";
    return false;
  }
  char ch = key[0];
  if ((ch >= 'a' && ch <= 'z') || ch == '$' ||
      (ch >= 'A' && ch <= 'Z') || ch == '_') {
    for (size_t i = 1; i < len; ++i) {
      ch = key[i];
      if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
          (ch >= 'A' && ch <= 'Z') || ch == '$' || ch == '_') {
        continue;
      }
      std::cerr << "The " << type << " need to be a valid variable name.";
      return false;
    }
    return true;
  } else {
    std::cerr << "The " << type << " need to be a valid variable name.";
    return false;
  }
}

bool Sdk::AssertProperties(const utils::ObjectNode& properties) {
  for (std::map<string, utils::ObjectNode::ValueNode>::const_iterator iter = properties.properties_map_.begin();
       iter != properties.properties_map_.end(); ++iter) {
    RETURN_IF_ERROR(AssertKey("Property Key", iter->first));

    if ("$time" == iter->first &&
        iter->second.node_type_ != utils::ObjectNode::DATETIME) {
      std::cerr << "The property '$time' should be DateTime type.";
      return false;
    } else if ("$project" == iter->first &&
               iter->second.node_type_ != utils::ObjectNode::STRING) {
      std::cerr << "The property '$project' should be String type.";
      return false;
    }
  }
  return true;
}

void Sdk::Shutdown() {
  if (instance_ != NULL) {
    delete instance_;
    instance_ = NULL;
  }
}

bool Sdk::Flush() {
  if (instance_) {
    return instance_->consumer_->Flush();
  }
  return false;
}

bool Sdk::FlushPart(size_t part_size, bool drop_failed_record) {
  if (instance_) {
    return instance_->consumer_->FlushPart(part_size, drop_failed_record);
  }
  return false;
}

void Sdk::ClearQueue() {
  if (instance_) {
    instance_->consumer_->Clear();
  }
}

void Sdk::Track(const string& event_name, const PropertiesNode& properties) {
  if (instance_) {
    instance_->AddEvent("track", event_name, properties, instance_->distinct_id_, "");
  }
}

void Sdk::Track(const string& event_name) {
  PropertiesNode properties_node;
  Track(event_name, properties_node);
}

void Sdk::Login(const string& login_id) {
  if (instance_) {
    PropertiesNode properties_node;
    instance_->AddEvent("track_signup", "$SignUp", properties_node, login_id, instance_->distinct_id_);
    instance_->distinct_id_ = login_id;
    instance_->is_login_id_ = true;
  }
}

void Sdk::Identify(const string& distinct_id, bool is_login_id) {
  if (instance_) {
    instance_->distinct_id_ = distinct_id;
    instance_->is_login_id_ = is_login_id;
  }
}

void Sdk::ProfileSet(const PropertiesNode& properties) {
  if (instance_) {
    instance_->AddEvent("profile_set", "", properties, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileSetString(const string& property_name, const string& str_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetString(property_name, str_value);
    instance_->AddEvent("profile_set", "", properties_node, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileSetNumber(const string& property_name, int number_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetNumber(property_name, number_value);
    instance_->AddEvent("profile_set", "", properties_node, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileSetNumber(const string& property_name, double number_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetNumber(property_name, number_value);
    instance_->AddEvent("profile_set", "", properties_node, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileSetBool(const string& property_name, bool bool_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetBool(property_name, bool_value);
    instance_->AddEvent("profile_set", "", properties_node, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileSetOnce(const PropertiesNode& properties) {
  if (instance_) {
    instance_->AddEvent("profile_set_once", "", properties, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileSetOnceString(const string& property_name, const string& str_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetString(property_name, str_value);
    instance_->AddEvent("profile_set_once", "", properties_node, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileSetOnceNumber(const string& property_name, int number_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetNumber(property_name, number_value);
    instance_->AddEvent("profile_set_once", "", properties_node, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileSetOnceNumber(const string& property_name, double number_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetNumber(property_name, number_value);
    instance_->AddEvent("profile_set_once", "", properties_node, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileSetOnceBool(const string& property_name, bool bool_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetBool(property_name, bool_value);
    instance_->AddEvent("profile_set_once", "", properties_node, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileIncrement(const PropertiesNode& properties) {
  if (instance_) {
    instance_->AddEvent("profile_increment", "", properties, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileIncrement(const string& property_name, int number_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetNumber(property_name, number_value);
    instance_->AddEvent("profile_increment", "", properties_node, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileAppend(const PropertiesNode& properties) {
  if (instance_) {
    instance_->AddEvent("profile_append", "", properties, instance_->distinct_id_, "");
  }
}

void Sdk::ProfileAppend(const string& property_name, const string& str_value) {
  if (instance_) {
    PropertiesNode properties_node;
    std::vector<string> str_vector;
    str_vector.push_back(str_value);
    properties_node.SetList(property_name, str_vector);
    instance_->AddEvent("profile_append", "", properties_node, instance_->distinct_id_, "");
  }
}

void Sdk::TrackInstallation(const string& event_name, const PropertiesNode& properties) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetString("$ios_install_source", "");
    instance_->AddEvent("track", event_name, properties_node, instance_->distinct_id_, "");
  }
}

void Sdk::ResetSuperProperties() {
  super_properties_->Clear();
  super_properties_->SetString("$lib", "cpp");
  super_properties_->SetString("$lib_version", SA_SDK_VERSION);
}

Sdk::Sdk(const string& server_url,
         const string& data_file_path,
         int max_staging_record_count,
         const string& distinct_id,
         bool is_login_id)
  : consumer_(new DefaultConsumer(server_url, data_file_path, max_staging_record_count)),
    distinct_id_(distinct_id),
    is_login_id_(is_login_id),
    super_properties_(new PropertiesNode) {
  ResetSuperProperties();
}

Sdk::~Sdk() {
  if (consumer_ != NULL) {
    delete consumer_;
    consumer_ = NULL;
  }
  if (super_properties_ != NULL) {
    delete super_properties_;
    super_properties_ = NULL;
  }
}

}  // namespace sensors_analytics
