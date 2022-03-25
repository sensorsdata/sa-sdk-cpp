//
//  sensors_network.cpp
//  CPPDemo
//
//  Created by 彭远洋 on 2021/7/2.
//  Copyright © 2021 Sensors Data Inc. All rights reserved.
//

#include "sensors_network.h"

#include <curl/curl.h>
#include <zlib.h>

#include <algorithm>
#include <functional>

#if defined(__clang__) || defined(__GNUC__)
    #define SA_CPP_STANDARD __cplusplus
#elif defined(_MSC_VER)
    #define SA_CPP_STANDARD _MSVC_LANG
#endif

#if SA_CPP_STANDARD >= 201103L
    #define SA_CPP_11 true
#endif

namespace sensors_analytics {

using namespace std;

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

  explicit Connection(const string &base_url);

  ~Connection();

  void SetTimeout(int seconds);

  void AppendHeader(const string &key, const string &value);

  Response Post(const string &url, const string &data);

 private:
  Response PerformCurlRequest(const string &uri);

  CURL *curl_handle_;
  string base_url_;
  HeaderFields header_fields_;
  int timeout_;
  bool follow_redirects_;
  int max_redirects_;
  bool no_signal_;
  RequestInfo last_request_;
};

Response Post(const string &url, const string &ctype, const string &data,
              int timeout_second,
              const vector<pair<string, string> > &headers =
                  vector<pair<string, string> >());

namespace helpers {
size_t WriteCallback(void *data, size_t size, size_t nmemb, void *user_data);

size_t HeaderCallback(void *data, size_t size, size_t nmemb, void *user_data);

inline string &TrimLeft(string &s);   // NOLINT
inline string &TrimRight(string &s);  // NOLINT
inline string &Trim(string &s);       // NOLINT
}  // namespace helpers

Connection::Connection(const string &base_url)
    : last_request_(), header_fields_() {
  try {
    this->curl_handle_ = curl_easy_init();
    if (!this->curl_handle_) {
      throw runtime_error("Couldn't initialize curl handle");
    }
    this->base_url_ = base_url;
    this->timeout_ = 0;
    this->follow_redirects_ = false;
    this->max_redirects_ = -1l;
    this->no_signal_ = false;
  } catch (exception &err) {
    cerr << err.what() << endl;
  }
}

Connection::~Connection() {
  if (this->curl_handle_) {
    curl_easy_cleanup(this->curl_handle_);
  }
}

void Connection::AppendHeader(const string &key, const string &value) {
  this->header_fields_[key] = value;
}

void Connection::SetTimeout(int seconds) { this->timeout_ = seconds; }

/**
 * @brief helper function to get called from the actual request methods to
 * prepare the curlHandle for transfer with generic options, perform the
 * request and record some stats from the last request and then reset the
 * handle with curl_easy_reset to its default state. This will keep things
 * like connections and session ID intact but makes sure you can change
 * parameters on the object for another request.
 *
 * @param uri URI to query
 *
 * @return 0 on success and 1 on error
 */
Response Connection::PerformCurlRequest(const string &uri) {
  // init return type
  Response ret = {};

  string url = string(this->base_url_ + uri);
  string header_string;
  CURLcode res;
  curl_slist *header_list = NULL;

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
  curl_easy_setopt(this->curl_handle_, CURLOPT_HTTPHEADER, header_list);

  // 若使用 HTTPS，有两种配置方式，选用其中一种即可：
  // 1. 使用 CA 证书（下载地址 http://curl.haxx.se/ca/cacert.pem
  // ），去掉下面一行的注释，并指定证书路径，例如证书在当前目录下
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

Response Connection::Post(const string &url, const string &data) {
  /** Now specify we want to POST data */
  curl_easy_setopt(this->curl_handle_, CURLOPT_POST, 1L);
  /** set post fields */
  curl_easy_setopt(this->curl_handle_, CURLOPT_POSTFIELDS, data.c_str());
  curl_easy_setopt(this->curl_handle_, CURLOPT_POSTFIELDSIZE, data.size());

  return this->PerformCurlRequest(url);
}

size_t helpers::WriteCallback(void *data, size_t size, size_t nmemb,
                              void *user_data) {
  Response *r;
  r = reinterpret_cast<Response *>(user_data);
  r->body_.append(reinterpret_cast<char *>(data), size * nmemb);

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
size_t helpers::HeaderCallback(void *data, size_t size, size_t nmemb,
                               void *user_data) {
  Response *r;
  r = reinterpret_cast<Response *>(user_data);
  string header(reinterpret_cast<char *>(data), size * nmemb);
  size_t separator = header.find_first_of(':');
  if (string::npos == separator) {
    // roll with non seperated headers...
    Trim(header);
    if (0 == header.length()) {
      return (size * nmemb);  // blank line;
    }
    r->headers_[header] = "present";
  } else {
    string key = header.substr(0, separator);
    Trim(key);
    string value = header.substr(separator + 1);
    Trim(value);
    r->headers_[key] = value;
  }

  return (size * nmemb);
}

inline string &helpers::TrimLeft(string &s) {  // NOLINT
#if SA_CPP_11
  s.erase(s.begin(),
    find_if(s.begin(), s.end(), [](int c) {return !std::isspace(c);}));
#else
  s.erase(s.begin(),
    find_if(s.begin(), s.end(), not1(ptr_fun<int, int>(isspace))));
#endif
  return s;
}

inline string &helpers::TrimRight(string &s) {  // NOLINT
#if SA_CPP_11
  s.erase(
    find_if(s.rbegin(), s.rend(), [](int c) {return !std::isspace(c);}).base(),
    s.end());
#else
  s.erase(
    find_if(s.rbegin(), s.rend(), not1(ptr_fun<int, int>(isspace))).base(),
    s.end());
#endif
  return s;
}

inline string &helpers::Trim(string &s) {  // NOLINT
  return TrimLeft(TrimRight(s));
}

Response Post(const string &url, const string &data, int timeout_second,
              const vector<HeaderFieldItem> &headers) {
  Response ret;
  Connection *conn;
  try {
    conn = new Connection("");
  } catch (runtime_error &e) {
    cerr << e.what() << endl;
    Response response;
    response.code_ = -1;
    response.body_ = e.what();
    return response;
  }

  conn->SetTimeout(timeout_second);
  for (vector<HeaderFieldItem>::const_iterator iterator = headers.begin();
       iterator != headers.end(); ++iterator) {
    conn->AppendHeader(iterator->first, iterator->second);
  }
  ret = conn->Post(url, data);
  delete conn;
  return ret;
}
}
