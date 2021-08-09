//
//  sensors_network.h
//  CPPDemo
//
//  Created by 彭远洋 on 2021/7/2.
//  Copyright © 2021 Sensors Data Inc. All rights reserved.
//

#ifndef sensors_network_h
#define sensors_network_h

#include <iostream>
#include <map>
#include <vector>

namespace sensors_analytics {
using namespace std;

typedef map<string, string> HeaderFields;
typedef pair<string, string> HeaderFieldItem;

typedef struct {
  int code_;
  string body_;
  HeaderFields headers_;
} Response;

Response Post(const string &url, const string &data, int timeout_second,
              const vector<HeaderFieldItem> &headers);
}  // namespace sensors_network

#endif /* sensors_analytics_h */
