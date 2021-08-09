//
//  sensors_utils.h
//  CPPDemo
//
//  Created by 彭远洋 on 2021/7/3.
//  Copyright © 2021 Sensors Data Inc. All rights reserved.
//

#ifndef sensors_utils_h
#define sensors_utils_h

#include <stdio.h>

#include <iostream>
#include <map>
#include <vector>

namespace sensors_analytics {
using namespace std;

class UrlParser {
 public:
  static UrlParser *parseUrl(string urlstr);
  string scheme;
  string hostName;
  string port;
  string path;
  string query;
  map<string, string> queryItems;
  string fragment;

 private:
  void parse();
  string mRawUrl;
};

string UrlWithoutQuery(UrlParser *parser);

vector<string> Split(const string &str, const string &pattern);
string Splice(const vector<string> &array, const string &pattern);

}

#endif
