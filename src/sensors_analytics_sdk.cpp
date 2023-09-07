/*
 * Copyright 2015－2021 Sensors Data Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sensors_analytics_sdk.h"
#include "sensors_network.h"

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

const std::string kDefaultLoginIdKey = "$identity_login_id";
const std::string kDefaultAnonymousIdKey = "$identity_anonymous_id";
const std::string kDefaultDistinctIdKey = "$identity_distinct_id";

namespace sensors_analytics {
namespace utils {

int64_t CurrentTimestamp() {
    int64_t current_timestamp;
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
    current_timestamp = (long long) now.tv_sec * 1000 + (long) (now.tv_usec / 1000);
#endif
    return current_timestamp;
}

int64_t GenerateTrackId() {
    string first = std::to_string(rand() % 99 + 100);
    string first_sub = first.substr(first.length() - 2, 2);

    string second = std::to_string(rand() % 999 + 1000);
    string second_sub = second.substr(second.length() - 3, 3);

    string timestamp = std::to_string(CurrentTimestamp());
    string timestamp_sub = timestamp.substr(timestamp.length() - 4, 4);

    return std::stoi(first_sub + second_sub + timestamp_sub);
}

string UrlEncode(const string &data) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;
  for (std::string::size_type i = 0; i < data.size(); ++i) {
    unsigned char c = data[i];
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

unsigned char DecimalFromHex(unsigned char x) {
    unsigned char y = '\0';
    if (x >= 'A' && x <= 'Z') y = x - 'A' + 10;
    else if (x >= 'a' && x <= 'z') y = x - 'a' + 10;
    else if (x >= '0' && x <= '9') y = x - '0';
    return y;
}

string UrlDecode(const string &data)
{
    std::string result = "";
    size_t length = data.length();
    for (size_t i = 0; i < length; i++)
    {
        if (data[i] == '+') result += ' ';
        else if (data[i] == '%') {
            unsigned char high = DecimalFromHex((unsigned char)data[++i]);
            unsigned char low = DecimalFromHex((unsigned char)data[++i]);
            result += high * 16 + low;
        }
        else result += data[i];
    }
    return result;
}

void ObjectNode::SetNumber(const string &property_name, double value) {
  properties_map_[property_name] = ValueNode(value);
}

void ObjectNode::SetNumber(const string &property_name, int32_t value) {
  properties_map_[property_name] = ValueNode(static_cast<int64_t>(value));
}

void ObjectNode::SetNumber(const string &property_name, int64_t value) {
  properties_map_[property_name] = ValueNode(value);
}

static const size_t kStringPropertyValueMaxLength = 8192;

bool CheckUtf8Valid(const string &str) {
  // https://stackoverflow.com/a/1031773
  const unsigned char *bytes = (const unsigned char *) str.data();
  const unsigned char *begin = bytes;
  while (bytes - begin < (int)str.length()) {
    if ((bytes[0] == 0x09 || bytes[0] == 0x0A || bytes[0] == 0x0D ||
        (0x20 <= bytes[0] && bytes[0] <= 0x7E))) {
      bytes += 1;
      continue;
    }
    if (((0xC2 <= bytes[0] && bytes[0] <= 0xDF)
        && (0x80 <= bytes[1] && bytes[1] <= 0xBF))) {
      bytes += 2;
      continue;
    }
    if ((bytes[0] == 0xE0 && (0xA0 <= bytes[1] && bytes[1] <= 0xBF) &&
        (0x80 <= bytes[2] && bytes[2] <= 0xBF)) ||
        (((0xE1 <= bytes[0] && bytes[0] <= 0xEC) || bytes[0] == 0xEE
            || bytes[0] == 0xEF) &&
            (0x80 <= bytes[1] && bytes[1] <= 0xBF)
            && (0x80 <= bytes[2] && bytes[2] <= 0xBF)) ||
        (bytes[0] == 0xED && (0x80 <= bytes[1] && bytes[1] <= 0x9F) &&
            (0x80 <= bytes[2] && bytes[2] <= 0xBF))) {
      bytes += 3;
      continue;
    }
    if ((bytes[0] == 0xF0 && (0x90 <= bytes[1] && bytes[1] <= 0xBF) &&
        (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
        (0x80 <= bytes[3] && bytes[3] <= 0xBF)) ||
        ((0xF1 <= bytes[0] && bytes[0] <= 0xF3)
            && (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
            (0x80 <= bytes[2] && bytes[2] <= 0xBF)
            && (0x80 <= bytes[3] && bytes[3] <= 0xBF)) ||
        (bytes[0] == 0xF4 && (0x80 <= bytes[1] && bytes[1] <= 0x8F) &&
            (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
            (0x80 <= bytes[3] && bytes[3] <= 0xBF))) {
      bytes += 4;
      continue;
    }
    return false;
  }
  return bytes - begin == str.length();
}
#if VS2015
//utf8 string to wide
std::wstring Utf8ToNative(const std::string& input, std::string* out_error) {
    int input_len = static_cast<int>(input.size());

    if (input_len == 0) {
        return L"";
    }

    auto conversion_func = [&](wchar_t* output, int output_size) {
        return ::MultiByteToWideChar(CP_UTF8, 0, input.data(), input_len, output,
            output_size);
    };

    int output_len = conversion_func(nullptr, 0);
    if (output_len <= 0) {
        DWORD error = ::GetLastError();
        if (out_error) {
            *out_error = "Utf8ToNative failed with code " + error;
        }
        return L"";
    }

    int output_terminated_len = output_len + 1;
    std::wstring output(output_terminated_len, L'\0');
    int converted_len = conversion_func(&output[0], output_len);
    if (converted_len <= 0 || converted_len >= output_terminated_len ||
        output[output_len] != '\0') {
        if (out_error) {
            *out_error =
                "Utf8ToNative failed: MultiByteToWideChar returned " + converted_len;
        }
        return L"";
    }

    output.resize(converted_len);
    return output;
}

//wide to utf8
std::string NativeToUtf8(const wchar_t* input, size_t input_size,
    std::string* out_error) {
    int input_len = static_cast<int>(input_size);
    if (input_len == 0) {
        return "";
    }

    auto conversion_func = [&](char* output, int output_size) {
        return ::WideCharToMultiByte(CP_UTF8, 0, input, input_len, output,
            output_size, nullptr, nullptr);
    };

    int output_len = conversion_func(nullptr, 0);
    if (output_len <= 0) {
        if (out_error) {
            DWORD error = ::GetLastError();
            *out_error = "NativeToUtf8 failed with code " + std::to_string(error);
        }
        return "";
    }

    int output_terminated_len = output_len + 1;
    std::string output(output_terminated_len, '\0');

    int converted_len = conversion_func(&output[0], output_len);
    if (converted_len <= 0 || converted_len >= output_terminated_len ||
        output[output_len] != '\0') {
        if (out_error) {
            *out_error =
                "NativeToUtf8 failed: WideCharToMultiByte returned " + converted_len;
        }

        return "";
    }

    output.resize(converted_len);
    return output;
}

std::string NativeToUtf8(const std::wstring& input, std::string* out_error) {
    return NativeToUtf8(input.c_str(), input.size(), out_error);
}
#endif // VS2015


std::string GetDistinctId(const map<string, string>& identities) {
    if (identities.empty()) {
        return "";
    }
    string distinct_id;
    for (auto const& identity : identities) {
        if (identity.first == kDefaultLoginIdKey || identity.first == kDefaultAnonymousIdKey || identity.first == kDefaultDistinctIdKey) {
            distinct_id = identity.second;
            break;
        }
    }
    if (distinct_id.empty()) {
        distinct_id = identities.begin()->second;
    }
    return distinct_id;
}

void ObjectNode::SetString(const string &property_name, const string &value) {
  if (value.length() > kStringPropertyValueMaxLength) {
    std::cerr << "String property '" << property_name
              << "' is too long, value: " << value << std::endl;
    return;
  }
  if (!CheckUtf8Valid(value)) {
    std::cerr << "String property '" << property_name
              << "' is not valid UTF-8 string, value: " << value
              << std::endl;
    return;
  }
  properties_map_[property_name] = ValueNode(value);
}

#if VS2015
void ObjectNode::SetString(const string& property_name, const wstring& value) {
    ObjectNode::SetString(property_name, utils::NativeToUtf8(value, nullptr));
}
#endif // VS2015

void ObjectNode::SetString(const string &property_name, const char *value) {
  if (value == NULL) {
    std::cerr << "String property '" << property_name
              << "' value is NULL"<< std::endl;
    return;
  }
  SetString(property_name, string(value));
}

void ObjectNode::SetBool(const string &property_name, bool value) {
  properties_map_[property_name] = ValueNode(value);
}

void
ObjectNode::SetObject(const string &property_name, const ObjectNode &value) {
  properties_map_[property_name] = ValueNode(value);
}

void ObjectNode::SetList(const string &property_name,
                         const std::vector<string> &value) {
  properties_map_[property_name] = ValueNode(value);
}

void ObjectNode::SetDateTime(const string &property_name,
                             const time_t seconds,
                             int milliseconds) {
  properties_map_[property_name] = ValueNode(seconds, milliseconds);
}

void utils::ObjectNode::SetDateTime(const string &property_name,
                                    const string &value) {
  properties_map_[property_name] = ValueNode(value);
}

void ObjectNode::Clear() {
  properties_map_.clear();
}

void ObjectNode::DumpNode(const ObjectNode &node, string *buffer) {
  *buffer += '{';
  bool first = true;

  for (std::map<string, ValueNode>::const_iterator
           iterator = node.properties_map_.begin();
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

void ObjectNode::ValueNode::DumpString(const string &value, string *buffer) {
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

void ObjectNode::ValueNode::DumpList(const std::vector<string> &value,
                                     string *buffer) {
  *buffer += '[';
  bool first = true;
  for (std::vector<string>::const_iterator iterator = value.begin();
       iterator != value.end(); ++iterator) {
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

void ObjectNode::ValueNode::DumpDateTime(const time_t &seconds,
                                         int milliseconds,
                                         string *buffer) {
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

string ObjectNode::ToJson(const ObjectNode &node) {
  string buffer;
  DumpNode(node, &buffer);
  return buffer;
}

void ObjectNode::MergeFrom(const utils::ObjectNode &another_node) {
  for (std::map<string, ValueNode>::const_iterator
           iterator = another_node.properties_map_.begin();
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

utils::ObjectNode::ValueNode::ValueNode(const string &value)
    : node_type_(STRING),
      string_data_(value) {}

utils::ObjectNode::ValueNode::ValueNode(bool value) : node_type_(BOOL) {
  value_.bool_value = value;
}

utils::ObjectNode::ValueNode::ValueNode(const utils::ObjectNode &value)
    : node_type_(OBJECT) {
  object_data_ = value;
}

utils::ObjectNode::ValueNode::ValueNode(const std::vector<string> &value)
    : node_type_(LIST),
      list_data_(value) {}

utils::ObjectNode::ValueNode::ValueNode(time_t seconds, int milliseconds)
    : node_type_(DATETIME) {
  value_.date_time_value.seconds = seconds;
  value_.date_time_value.milliseconds = milliseconds;
}

void
utils::ObjectNode::ValueNode::ToStr(const utils::ObjectNode::ValueNode &node,
                                    string *buffer) {
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

void ObjectNode::ValueNode::DumpNumber(double value, string *buffer) {
  std::ostringstream buf;
  buf.precision(15);//覆盖默认精度
  buf.imbue(locale("C"));//设置 buf 的 locale 为 C,即为 unicode 编码
  buf << value;
  *buffer += buf.str();
}

void ObjectNode::ValueNode::DumpNumber(int64_t value, string *buffer) {
  std::ostringstream buf;
  buf.imbue(locale("C"));//设置 buf 的 locale 为 C,即为 unicode 编码
  buf << value;
  *buffer += buf.str();
}

}  // namespace utils

class HttpSender {
 public:
  explicit HttpSender(const string &server_url,
                      const std::vector<std::pair<string,
                                                  std::string> > &http_headers
                      = std::vector<std::pair<string, std::string> >());

  bool Send(const string &data, const std::vector<std::pair<string,string> > &http_headers);

 private:
  static bool
  CompressString(const string &str, string *out_string, int compression_level);

  static bool EncodeToRequestBody(const string &data, string *request_body);

  static string Base64Encode(const string &data);

  friend class Sdk;

  static const int kRequestTimeoutSecond = 3;
  string server_url_;
  std::vector<std::pair<string, std::string> > http_headers_;
};

HttpSender::HttpSender(const string &server_url,
                       const std::vector<std::pair<string,
                                                   string> > &http_headers) :
    server_url_(server_url), http_headers_(http_headers) {}

bool HttpSender::Send(const string &data, const std::vector<std::pair<string,string> > &http_headers) {
  string request_body;
  if (!EncodeToRequestBody(data, &request_body)) {
    return false;
  }
  Response response = Post(server_url_,
                           request_body,
                           kRequestTimeoutSecond,
                           http_headers);
  if (response.code_ != 200) {
    std::cerr << "SensorsAnalytics SDK send failed: " << response.body_
              << std::endl;
    return false;
  }
  return true;
}

bool HttpSender::CompressString(const string &str,
                                string *out_string,
                                int compression_level = Z_BEST_COMPRESSION) {
  z_stream zs;  // z_stream is zlib's control structure
  memset(&zs, 0, sizeof(zs));

  if (deflateInit2(&zs, compression_level, Z_DEFLATED,
                   15 | 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
    std::cerr << "deflateInit2 failed while compressing." << std::endl;
    return false;
  }

  zs.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(str.data()));
  zs.avail_in = static_cast<uInt>(str.size());  // set the z_stream's input

  int ret;
  char out_buffer[32768];

  // retrieve the compressed bytes blockwise
  do {
    zs.next_out = reinterpret_cast<Bytef *>(out_buffer);
    zs.avail_out = sizeof(out_buffer);

    ret = deflate(&zs, Z_FINISH);

    if (out_string->size() < zs.total_out) {
      // append the block to the output string
      out_string->append(out_buffer, zs.total_out - out_string->size());
    }
  } while (ret == Z_OK);

  deflateEnd(&zs);

  if (ret != Z_STREAM_END) {  // an error occurred that was not EOF
    std::cerr << "Exception during zlib compression: (" << ret << ") " << zs.msg
              << std::endl;
    return false;
  }

  return true;
}

static const char kBase64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string HttpSender::Base64Encode(const string &data) {
  const unsigned char
      *bytes_to_encode = reinterpret_cast<const unsigned char *>(data.data());
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
      char_array_4[1] =
          ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] =
          ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
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
    char_array_4[1] =
        ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] =
        ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;
    for (j = 0; (j < i + 1); j++)
      ret += kBase64Chars[char_array_4[j]];
    while ((i++ < 3))
      ret += '=';
  }
  return ret;
}

bool HttpSender::EncodeToRequestBody(const string &data, string *request_body) {
  string compressed_data;
  if (!CompressString(data, &compressed_data)) {
    return false;
  }
  const string base64_encoded_data = Base64Encode(compressed_data);
  *request_body = "data_list=" + utils::UrlEncode(base64_encoded_data) + "&gzip=1";
  return true;
}

void PropertiesNode::SetObject(const string &property_name,
                               const utils::ObjectNode &value) {}

class DefaultConsumer {
 public:
  DefaultConsumer(const string &server_url,
                  const string &data_file_path,
                  int max_staging_record_count);
#if VS2015
  DefaultConsumer(const string& server_url, const wstring& data_file_path, int max_staging_record_count);
#endif // VS2015

  void Init();

  void Send(const utils::ObjectNode &record);

  // 触发一次发送
  // 发送最多 kFlushAllBatchSize(30) 条数据
  // 当 drop_failed_record 为 true 时，发送失败则丢弃这些数据不再发送
  // 当 drop_failed_record 为 false 时，发送失败仍保留在队列里，下次再试
  bool FlushPart(size_t part_size, bool drop_failed_record);

  // 发送当前所有数据，如果发送中断（失败）返回 false，全部发送成功返回 true
  bool Flush();

  // 清空发送队列，包括磁盘文件
  void Clear();

  void EnableLog(bool enable_log);

  // 使用追加的方式把队列中数据添加到本地文件中，默认是 false
  void AppendRecordsToDisk(bool enable);

  //将队列中的所有数据直接存到本地文件中，并清空队列内容
  void DumpAllRecordsToDisk();

  string request_header_cookie;

  bool enable_log_;

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
    LockGuard(SA_MUTEX *mutex) : mutex_(mutex) {
      SA_MUTEX_LOCK(mutex_);
    }

    ~LockGuard() {
      SA_MUTEX_UNLOCK(mutex_);
    }

   private:
    SA_MUTEX *mutex_;
  };

  std::deque<string> records_;
#if VS2015
  wstring data_file_path_;  
#else
  string data_file_path_;
#endif // VS2015
  
  int max_staging_record_count_;
  bool need_try_load_from_disk_;
  bool append_records_to_disk_;
  HttpSender *sender_;
};

DefaultConsumer::DefaultConsumer(const string &server_url,
                                 const string &data_file_path,
                                 int max_staging_record_count)
    :
#if VS2015
    data_file_path_(utils::Utf8ToNative(data_file_path, nullptr)),
#else
    data_file_path_(data_file_path),
#endif // VS2015
      max_staging_record_count_(max_staging_record_count),
      need_try_load_from_disk_(true),
      enable_log_(false),
      append_records_to_disk_(false),
      sender_(new HttpSender(server_url)) {}

#if VS2015
DefaultConsumer::DefaultConsumer(const string& server_url,
    const wstring& data_file_path,
    int max_staging_record_count)
    :data_file_path_(data_file_path),
    max_staging_record_count_(max_staging_record_count),
    need_try_load_from_disk_(true),
    enable_log_(false),
    append_records_to_disk_(false),
    sender_(new HttpSender(server_url)) {}
#endif // VS2015


void DefaultConsumer::Send(const utils::ObjectNode &record) {
  const string json_record = utils::ObjectNode::ToJson(record);
  if (enable_log_) {
    std::cout << "add record:" + json_record << std::endl;
  }
  LockGuard records_lock(&records_mutex_);
  records_.push_back(json_record);
  if (records_.size() > (size_t) max_staging_record_count_) {
    records_.pop_front();
    if (enable_log_) {
      std::cout << "record is full, delete record" << std::endl;
    }
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
  for (std::vector<string>::const_iterator iter = sending_records.begin();
       iter != sending_records.end(); ++iter) {
    if (iter != sending_records.begin()) {
      buffer << ',';
    }
    buffer << *iter;
  }
  buffer << ']';
  if (enable_log_) {
    std::cout << "flush record : " + buffer.str() << std::endl;
  }

  // 添加自定义的 Cookie 信息
  std::vector<std::pair<string,string> > http_headers;
  if (request_header_cookie.length() > 0 ) {
    std::pair<string, string> cookie;
    cookie.first = "Cookie";
    cookie.second = request_header_cookie;
    http_headers.insert(http_headers.begin(), cookie);
  }
  bool send_result = sender_->Send(buffer.str(), http_headers);

  if (!send_result && !drop_failed_record) {
    // 如果发送失败并且发送失败的不能丢，那么放回发送队列
      try {
        {
            LockGuard records_lock(&records_mutex_);
            size_t records_remain_size = max_staging_record_count_ - records_.size();
            if (records_remain_size > 0) {
              // 需要从最前面补满 records_，从 sending_records 的 begin_idx 元素到最后一个元素
              size_t begin_idx = sending_records.size() > records_remain_size ?
                                 sending_records.size() - records_remain_size : 0;
              std::vector<string>::iterator
                  copy_sending_begin = sending_records.begin() + begin_idx;
              records_.insert(records_.begin(),
                              copy_sending_begin,
                              sending_records.end());
            }
        }
      } catch (std::exception& err) {
          std::cerr << "Exception when flush failed: (" << err.what() << ") " << std::endl;
      } catch (...) {
          // 规避 Flush 时接口请求异常发生的偶现异常情况
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

void DefaultConsumer::EnableLog(bool enable_log) {
  enable_log_ = enable_log;
}

void DefaultConsumer::AppendRecordsToDisk(bool enable) {
    append_records_to_disk_ = enable;
}

void DefaultConsumer::DumpAllRecordsToDisk() {
    if (!append_records_to_disk_) {
        return;
    }
    LockGuard records_lock(&records_mutex_);
#if VS2015
        std::wofstream staging_ofs(data_file_path_, ios::app);     
#else
        std::ofstream staging_ofs(data_file_path_.c_str(), ios::app);
#endif // VS2015

    for (int index = 0; index < records_.size(); index++) {
        staging_ofs << records_[index].c_str() << endl;
    }

    staging_ofs.close();
    records_.clear();
}

DefaultConsumer::~DefaultConsumer() {
  Close();
}

inline void DefaultConsumer::TruncateStagingFile() {
#if VS2015
    std::wofstream staging_ofs
    (data_file_path_, std::ofstream::out | std::ofstream::trunc);
#else
    std::ofstream staging_ofs
    (data_file_path_.c_str(), std::ofstream::out | std::ofstream::trunc);
#endif // VS2015
  staging_ofs.close();
}

void DefaultConsumer::LoadRecordFromDisk() {
  LockGuard records_lock(&records_mutex_);
  if (!need_try_load_from_disk_ && !append_records_to_disk_) {
    return;
  }
  size_t memory_remain_size = max_staging_record_count_ - records_.size();
  if (memory_remain_size > 0) {
    // 读文件里最后 memory_remain_size 条数据
    std::deque<string> record_buffer;
    string line;
#if VS2015
    std::fstream staging_ifs(data_file_path_, std::ofstream::in);
#else
    std::ifstream staging_ifs(data_file_path_.c_str(), std::ofstream::in);
#endif // VS2015
    
    while (std::getline(staging_ifs, line)) {
      if (line.length() == 0 || line[0] != '{'
          || line[line.length() - 1] != '}') {
        continue;
      }
#if VS2015
      record_buffer.push_back(line);
#else
      record_buffer.push_back(line);
#endif // VS2015
      if (record_buffer.size() > memory_remain_size) {
        record_buffer.pop_front();
      }
    }
    staging_ifs.close();

    records_.insert(records_.begin(),
                    record_buffer.begin(),
                    record_buffer.end());
  }
  TruncateStagingFile();
  // 标记不需要尝试读磁盘文件
  need_try_load_from_disk_ = false;
}

inline void DefaultConsumer::DumpRecordToDisk() {
#if VS2015
    std::wofstream staging_ofs(data_file_path_, ios::app);
#else
    std::ofstream staging_ofs(data_file_path_.c_str(), ios::app);
#endif // VS2015

    for (int index = 0; index < records_.size(); index++) {
        staging_ofs << records_[index].c_str() << endl;
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

Sdk *Sdk::instance_ = NULL;

/// class Sdk
#define RETURN_IF_ERROR(stmt) do { if (!stmt) return false; } while (false)

bool Sdk::Init(const std::string &data_file_path,
               const std::string &server_url,
               const std::string &distinct_id,
               bool is_login_id,
               int max_staging_record_count) {
    RETURN_IF_ERROR(AssertId("Distinct ID", distinct_id));
    if (!instance_) {
        std::map<string, string> identities;
        instance_ = new Sdk(server_url,
            data_file_path,
            max_staging_record_count,
            distinct_id,
            is_login_id,
            identities);
        instance_->consumer_->Init();
        // 生成 track_id 随机数算子
        srand((unsigned)time(NULL));
    }
    return true;
}
#if VS2015

bool Sdk::Init(const std::wstring& data_file_path,
    const std::string& server_url,
    const std::string& distinct_id,
    bool is_login_id,
    int max_staging_record_count) {
    RETURN_IF_ERROR(AssertId("Distinct ID", distinct_id));
    if (!instance_) {
        std::map<string, string> identities;
        instance_ = new Sdk(server_url,
            data_file_path,
            max_staging_record_count,
            distinct_id,
            is_login_id,
            identities);
        instance_->consumer_->Init();
        // 生成 track_id 随机数算子
        srand((unsigned)time(NULL));
    }
    return true;
}
#endif // VS2015

//ID-Mapping3
bool Sdk::Init(const string& data_file_path, const string& server_url,
    const string& distinct_id, int max_staging_record_count, const map<string, string>& identities) {
    RETURN_IF_ERROR(AssertId("Distinct ID", distinct_id));
    if (!instance_) {
        instance_ = new Sdk(server_url,
            data_file_path,
            max_staging_record_count,
            distinct_id,
            false,
            identities);
        instance_->consumer_->Init();
        // 生成 track_id 随机数算子
        srand((unsigned)time(NULL));
    }
    return true;
}
bool Sdk::Init(const string& data_file_path, const string& server_url,
    int max_staging_record_count, const map<string, string>& identities) {
    string distinct_id = utils::GetDistinctId(identities);
    return Sdk::Init(data_file_path, server_url, distinct_id, max_staging_record_count, identities);
}

#if VS2015
bool Sdk::Init(const wstring& data_file_path, const string& server_url,
    const string& distinct_id, int max_staging_record_count, const map<string, string>& identities) {
    RETURN_IF_ERROR(AssertId("Distinct ID", distinct_id));
    if (!instance_) {
        instance_ = new Sdk(server_url,
            data_file_path,
            max_staging_record_count,
            distinct_id,
            false,
            identities);
        instance_->consumer_->Init();
        // 生成 track_id 随机数算子
        srand((unsigned)time(NULL));
    }
    return true;
}

bool Sdk::Init(const wstring& data_file_path, const string& server_url,
    int max_staging_record_count, const map<string, string>& identities) {
    string distinct_id = utils::GetDistinctId(identities);
    return Sdk::Init(data_file_path, server_url, distinct_id, max_staging_record_count, identities);
}
#endif // VS2015


void Sdk::Bind(const string& key, const string& value) {
    if (key == kDefaultLoginIdKey) {
        std::cout << "bind key not valid, should not use " << kDefaultLoginIdKey << std::endl;
        return;
    }
    if (key == kDefaultAnonymousIdKey) {
        std::cout << "bind key not valid, should not use " << kDefaultAnonymousIdKey << std::endl;
        return;
    }
    if (key == instance_->loginIdKey_) {
        std::cout << "bind key not valid, should not use " << instance_->loginIdKey_ << std::endl;
        return;
    }
    instance_->identities_[key] = value;
    Track("$BindID");
}
void Sdk::Login(const string& key, const string& loginId) {
    if (!instance_) {
        return;
    }
    if (loginId.length() > 255) {
        cout << "loginId:" << loginId << "is beyond the maximum length 255" << endl;
        return;
    }

    if (key == kDefaultLoginIdKey && instance_->distinct_id_ == loginId) {
        return;
    }
    if (instance_->identities_[key] == loginId) {
        return;
    }
    string lastLoginIdKey = instance_->loginIdKey_;
    instance_->loginIdKey_ = key;
    PropertiesNode properties_node;
    instance_->identities_[key] = loginId;
    string tempLoginId = (key == kDefaultLoginIdKey ? loginId : (key + "+" + loginId));
    instance_->AddEvent("track_signup",
        "$SignUp",
        properties_node,
        tempLoginId,
        instance_->distinct_id_);
    instance_->distinct_id_ = tempLoginId;
    instance_->is_login_id_ = true;
    if (key != lastLoginIdKey) {
        instance_->identities_.erase(lastLoginIdKey);
    }

    instance_->Notify();
}
void Sdk::Reset(const string& distinct_id, const map<string, string>& identities) {
    if (!instance_) {
        return;
    }
    instance_->identities_ = identities;
    instance_->distinct_id_ = distinct_id;
    if (!instance_->loginIdKey_.empty()) {
        instance_->loginIdKey_.clear();
    }
}
void Sdk::Reset(const map<string, string>& identities) {
    string distinct_id = utils::GetDistinctId(identities);
    Sdk::Reset(distinct_id, identities);
}

void Sdk::EnableLog(bool enable) {
  if (instance_) {
      instance_->consumer_->EnableLog(enable);
  }
}

// 使用追加的方式把队列中数据添加到本地文件中，默认是 false
void Sdk::AppendRecordsToDisk(bool enable) {
    if (instance_) {
        instance_->consumer_->AppendRecordsToDisk(enable);
    }
}

//将队列中的所有数据直接存到本地文件中，并清空队列内容
void Sdk::DumpAllRecordsToDisk() {
    if (instance_) {
        instance_->consumer_->DumpAllRecordsToDisk();
    }
}

void Sdk::SetCookie(const string &cookie, bool encode) {
    if (instance_) {
        string encodedCookie = encode ? utils::UrlEncode(cookie) : cookie;
        instance_->consumer_->request_header_cookie = encodedCookie;
    }
}

string Sdk::GetCookie(bool decode) {
    if (instance_) {
        string cookie = instance_->consumer_->request_header_cookie;
        string decodeCookie = decode ? utils::UrlDecode(cookie) : cookie;
        return decodeCookie;
    }
    return "";
}

void Sdk::RegisterSuperProperties(const PropertiesNode &properties) {
  if (instance_) {
    instance_->super_properties_->MergeFrom(properties);
  }
}

void Sdk::ClearSuperProperties() {
  if (instance_) {
    instance_->ResetSuperProperties();
  }
}

bool Sdk::AddEvent(const string &action_type,
                   const string &event_name,
                   const utils::ObjectNode &properties,
                   const string &distinct_id,
                   const string &original_id) {
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
    current_timestamp =
        1000L * time_property_iter->second.value_.date_time_value.seconds +
            time_property_iter->second.value_.date_time_value.milliseconds;
    record_properties.properties_map_.erase(time_property_iter);
  } else {
    current_timestamp = utils::CurrentTimestamp();
  }

  string project;
  std::map<string, utils::ObjectNode::ValueNode>::iterator
      project_property_iter =
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

  //ID-Mapping3 identities
  if (!identities_.empty()) {
      utils::ObjectNode identities_node;
      for (auto const& identity : identities_) {
          identities_node.SetString(identity.first, identity.second);
      }
      record_node.SetObject("identities", identities_node);
  }

  // 新增 _track_id，用于过滤重复数据
  record_node.SetNumber("_track_id", utils::GenerateTrackId());

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

bool Sdk::AddItemEvent(const std::string &action_type,
                       const std::string &item_type,
                       const string &item_id,
                       const sensors_analytics::utils::ObjectNode &properties) {
  utils::ObjectNode record_properties;
  if (action_type == "item_set") {
    RETURN_IF_ERROR(AssertProperties(properties));
    record_properties.MergeFrom(properties);
  }
  RETURN_IF_ERROR(AssertKey("Item Type", item_type));
  RETURN_IF_ERROR(AssertId("Item Id", item_id));

  int64_t current_timestamp;
  std::map<string, utils::ObjectNode::ValueNode>::iterator time_property_iter =
      record_properties.properties_map_.find("$time");
  if (time_property_iter != record_properties.properties_map_.end()) {
    current_timestamp =
        1000L * time_property_iter->second.value_.date_time_value.seconds +
            time_property_iter->second.value_.date_time_value.milliseconds;
    record_properties.properties_map_.erase(time_property_iter);
  } else {
    current_timestamp = utils::CurrentTimestamp();
  }
  string project;
  std::map<string, utils::ObjectNode::ValueNode>::iterator
      project_property_iter =
      record_properties.properties_map_.find("$project");
  if (project_property_iter != record_properties.properties_map_.end()) {
    project = project_property_iter->second.string_data_;
    record_properties.properties_map_.erase(project_property_iter);
  }
  utils::ObjectNode lib_node;
  lib_node.SetString("$lib", "cpp");
  lib_node.SetString("$lib_version", SA_SDK_VERSION);
  lib_node.SetString("$lib_method", "code");

  utils::ObjectNode record_node;
  record_node.SetString("type", action_type);
  record_node.SetNumber("time", current_timestamp);
  if (record_properties.properties_map_.size() != 0) {
    record_node.SetObject("properties", record_properties);
  }
  record_node.SetObject("lib", lib_node);

  if (project.length() > 0) {
    record_node.SetString("project", project);
  }
  record_node.SetString("item_type", item_type);
  record_node.SetString("item_id", item_id);
  consumer_->Send(record_node);
  return true;
}

bool Sdk::AssertId(const string &type, const string &key) {
  if (key.length() < 1) {
    std::cerr << "The " << type << " is empty." << std::endl;
    return false;
  } else if (key.length() > 255) {
    std::cerr << "The " << type << " is too long, max length is 255."
              << std::endl;
    return false;
  }
  return true;
}

bool Sdk::AssertKey(const string &type, const string &key) {
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

bool Sdk::AssertProperties(const utils::ObjectNode &properties) {
  for (std::map<string, utils::ObjectNode::ValueNode>::const_iterator
           iter = properties.properties_map_.begin();
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

void Sdk::Track(const string &event_name, const PropertiesNode &properties) {
  if (instance_) {
    instance_->AddEvent("track",
                        event_name,
                        properties,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::Track(const string &event_name) {
  PropertiesNode properties_node;
  Track(event_name, properties_node);
}

void Sdk::ItemSet(const std::string &item_type, const std::string &item_id,
                  sensors_analytics::PropertiesNode &properties) {
  if (instance_) {
    instance_->AddItemEvent("item_set", item_type, item_id, properties);
  }
}

void Sdk::ItemDelete(const std::string &item_type, const std::string &item_id) {
  if (instance_) {
    PropertiesNode properties_node;
    instance_->AddItemEvent("item_delete", item_type, item_id, properties_node);
  }
}

void Sdk::Login(const string &login_id) {
    Sdk::Login(kDefaultLoginIdKey, login_id);
}

void Sdk::Identify(const string &distinct_id, bool is_login_id) {
  if (instance_) {
      // 当登录状态和 distinct_id 都未发生变化时，不更新 distinct_id 和 is_login_id
      if (is_login_id == instance_->is_login_id_ && distinct_id == instance_->distinct_id_) {
          return;
      }

    instance_->distinct_id_ = distinct_id;
    instance_->is_login_id_ = is_login_id;
    instance_->Notify();
  }
}

void Sdk::ProfileSet(const PropertiesNode &properties) {
  if (instance_) {
    instance_->AddEvent("profile_set",
                        "",
                        properties,
                        instance_->distinct_id_,
                        "");
  }
}

void
Sdk::ProfileSetString(const string &property_name, const string &str_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetString(property_name, str_value);
    instance_->AddEvent("profile_set",
                        "",
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileSetNumber(const string &property_name, int number_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetNumber(property_name, number_value);
    instance_->AddEvent("profile_set",
                        "",
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileSetNumber(const string &property_name, double number_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetNumber(property_name, number_value);
    instance_->AddEvent("profile_set",
                        "",
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileSetBool(const string &property_name, bool bool_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetBool(property_name, bool_value);
    instance_->AddEvent("profile_set",
                        "",
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileSetOnce(const PropertiesNode &properties) {
  if (instance_) {
    instance_->AddEvent("profile_set_once",
                        "",
                        properties,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileSetOnceString(const string &property_name,
                               const string &str_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetString(property_name, str_value);
    instance_->AddEvent("profile_set_once",
                        "",
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileSetOnceNumber(const string &property_name, int number_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetNumber(property_name, number_value);
    instance_->AddEvent("profile_set_once",
                        "",
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void
Sdk::ProfileSetOnceNumber(const string &property_name, double number_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetNumber(property_name, number_value);
    instance_->AddEvent("profile_set_once",
                        "",
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileSetOnceBool(const string &property_name, bool bool_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetBool(property_name, bool_value);
    instance_->AddEvent("profile_set_once",
                        "",
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileIncrement(const PropertiesNode &properties) {
  if (instance_) {
    instance_->AddEvent("profile_increment",
                        "",
                        properties,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileIncrement(const string &property_name, int number_value) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetNumber(property_name, number_value);
    instance_->AddEvent("profile_increment",
                        "",
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileAppend(const PropertiesNode &properties) {
  if (instance_) {
    instance_->AddEvent("profile_append",
                        "",
                        properties,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileAppend(const string &property_name, const string &str_value) {
  if (instance_) {
    PropertiesNode properties_node;
    std::vector<string> str_vector;
    str_vector.push_back(str_value);
    properties_node.SetList(property_name, str_vector);
    instance_->AddEvent("profile_append",
                        "",
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileUnset(const string &property_name) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetString(property_name, "");
    instance_->AddEvent("profile_unset",
                        "",
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ProfileDelete() {
  if (instance_) {
    PropertiesNode properties_node;
    instance_->AddEvent("profile_delete",
                        "",
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::TrackInstallation(const string &event_name,
                            const PropertiesNode &properties) {
  if (instance_) {
    PropertiesNode properties_node;
    properties_node.SetString("$ios_install_source", "");
    properties_node.MergeFrom(properties);
    instance_->AddEvent("track",
                        event_name,
                        properties_node,
                        instance_->distinct_id_,
                        "");
  }
}

void Sdk::ResetSuperProperties() {
  super_properties_->Clear();
  super_properties_->SetString("$lib", "cpp");
  super_properties_->SetString("$lib_version", SA_SDK_VERSION);
}

string Sdk::DistinctID() {
    return instance_ ? instance_->distinct_id_ :  "";
}

bool Sdk::IsLoginID() {
    return instance_ ? instance_->is_login_id_ :  false;

}

bool Sdk::IsEnableLog() {
    return instance_ ? instance_->consumer_->enable_log_ : false;
}

string Sdk::StagingFilePath() {
    return instance_ ? instance_->staging_file_path_ :  "";
}

void Sdk::Attach(UserAlterationObserver *observer) {
    if (instance_) {
        instance_->observers.push_back(observer);
    }
}

void Sdk::Detach(UserAlterationObserver *observer) {
    if (instance_) {
        instance_->observers.push_back(observer);
    }
}

void Sdk::Notify() {
    if (instance_) {
        vector<UserAlterationObserver *> list = instance_->observers;
        for (vector<UserAlterationObserver *>::iterator observer = list.begin(); observer != list.end(); observer++) {
            (*observer)->Update();
        }
    }
}

Sdk::Sdk(const string &server_url,
         const string &data_file_path,
         int max_staging_record_count,
         const string &distinct_id,
         bool is_login_id, 
         const map<string, string>& identities)
    : consumer_(new DefaultConsumer(server_url,
                                    data_file_path,
                                    max_staging_record_count)),
    distinct_id_(distinct_id),
    is_login_id_(is_login_id),
    staging_file_path_(data_file_path),
    super_properties_(new PropertiesNode),
    identities_(identities) {
    ResetSuperProperties();
}

#if VS2015
Sdk::Sdk(const string& server_url,
    const wstring& data_file_path,
    int max_staging_record_count,
    const string& distinct_id,
    bool is_login_id, 
    const map<string, string>& identities)
    : consumer_(new DefaultConsumer(server_url,
        data_file_path,
        max_staging_record_count)),
    distinct_id_(distinct_id),
    is_login_id_(is_login_id),
    staging_file_path_(utils::NativeToUtf8(data_file_path, nullptr)),
    super_properties_(new PropertiesNode),
    identities_(identities) {
    ResetSuperProperties();
}
#endif // 0

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
