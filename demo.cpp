//
// Created by Feng Jiajie on 2018/9/6.
//
// https://www.sensorsdata.cn/_manual/cpp_sdk.html

#include <string>
#include <cstdlib>
#include <iostream>
#include "sensors_analytics_sdk.h"

using std::string;

void SensorsDatTest();

std::string GenerateId();
int main() {
    SensorsDatTest();
    return 0;
}

void SensorsDatTest() {
    // 暂存文件路径，该文件用于进程退出时将内存中未发送的数据暂存在磁盘，下次发送时加载
    const string staging_file_path = "./staging_file";

    // 服务端数据接收地址
    const string server_url = "https://sdkdebugtest.datasink.sensorsdata.cn/sa?project=default&token=cfb8b60e42e0ae9b";

    // 随机生成 UUID 作为 distinct_id
    // 注意：这里只是作为 demo 演示，随机生成一个 ID，如果正式使用，可以生成使用其他格式的设备 ID，并且自己保存下来，下次构造 SDK 时使用之前相同的 ID 以标识同一设备。
    const string distinct_id = GenerateId();
    std::cout << "distinct_id: " << distinct_id << std::endl;
    // 神策 ID 分为 “设备 ID” 和 “登录 ID” 两种，随机生成的是 “设备 ID”
    const bool is_login_id = false;

    // 本地最多暂存（未调用 Flush 发送）的数据条数，超过该数值时，将从队首淘汰旧的数据
    const int max_staging_record_size = 200;

    // 初始化 SDK
    sensors_analytics::Sdk::Init(staging_file_path, server_url, distinct_id, is_login_id, max_staging_record_size);
    sensors_analytics::Sdk::EnableLog(true);
    // 设置公共属性，这些属性将自动设置在每个行为事件的属性里
    sensors_analytics::PropertiesNode super_properties;
    super_properties.SetString("app_name", "myapp");
    super_properties.SetString("platform", "PC");
    sensors_analytics::Sdk::RegisterSuperProperties(super_properties);

    // 如果是 App 新安装第一次启动，若需要渠道追踪模糊匹配（请见文档），可以调用
    sensors_analytics::PropertiesNode track_installation_properties;
    sensors_analytics::Sdk::TrackInstallation("AppInstall", track_installation_properties);

    // 记录一个行为事件
    sensors_analytics::PropertiesNode event_properties;
    event_properties.SetString("computer_name", "ABCXYZ");
    event_properties.SetNumber("test_number_int", 3);
    event_properties.SetNumber("test_number_double", 3.14);
    event_properties.SetBool("test_bool", true);
    std::string test_string = "测试字符串";
    event_properties.SetString("test_stl_string", test_string);
    event_properties.SetDateTime("test_time", time(NULL), 0);
    std::vector<std::string> test_list;
    test_list.push_back("item1");
    test_list.push_back("item2");
    event_properties.SetList("test_list", test_list);
    sensors_analytics::Sdk::Track("OpenApp", event_properties);
    // 当可以获取到用户的 “登录 ID” 时，使用登录接口设置 “登录 ID”
    // 此操作会在服务端进行 ID 关联，之后使用新的 ID 作为 distinct_id
    sensors_analytics::Sdk::Login("123456");

    // 设置一个用户属性
    sensors_analytics::Sdk::ProfileSetNumber("Age", 26);

    // 为数组类型的用户属性追加值
    sensors_analytics::Sdk::ProfileAppend("hobby", "movie");

    // 上面所有埋点都没有真正发送到服务端，当有网络的时候，请调用 Flush 手工触发发送
    // 注意：仅当调用 Flush 函数才会触发网络发送
    // 发送是阻塞的，可以考虑使用独立线程调用发送函数
    // 如果因为网络问题发送失败，函数返回值为 false
    bool flush_result = sensors_analytics::Sdk::Flush();
    std::cout << "send result: " << (flush_result ? "true" : "false") << std::endl;

    // 进程结束前没有 Flush 的数据将保存到 staging_file
    sensors_analytics::Sdk::Track("BuyTicket");
    sensors_analytics::Sdk::Shutdown();
}

#if defined(_WIN32)
#define snprintf sprintf_s
#endif

// 随机生成一个 ID
std::string GenerateId() {
    char str_uuid[80];
    srand(time(NULL));
    snprintf(str_uuid, sizeof(str_uuid),
             "%x%x-%x-%x-%x-%x%x%x",
             rand(),
             rand(),
             rand(),
             ((rand() & 0x0fff) | 0x4000),
             rand() % 0x3fff + 0x8000,
             rand(),
             rand(),
             rand());
    return str_uuid;
}
