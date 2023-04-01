/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/clock.h>
#include <aws/crt/Api.h>
#include <aws/crt/auth/Credentials.h>
#include <aws/crt/crypto/Hash.h>
#include <aws/crt/http/HttpConnection.h>
#include <aws/crt/http/HttpRequestResponse.h>
#include <aws/crt/io/Uri.h>
#include <aws/iot/MqttCommon.h>
#include <aws/iot/MqttClient.h>

#include <aws/crt/UUID.h>

#include <aws/common/command_line_parser.h>
#include <condition_variable>
#include <fstream>
#include <future>
#include <iostream>

#define AWS_MQTT5_CANARY_CLIENT_CREATION_SLEEP_TIME 10000000
#define AWS_MQTT5_CANARY_OPERATION_ARRAY_SIZE 10000
#define AWS_MQTT5_CANARY_TOPIC_ARRAY_SIZE 256
#define AWS_MQTT5_CANARY_CLIENT_MAX 50
#define AWS_MQTT5_CANARY_PAYLOAD_SIZE_MAX UINT16_MAX

using namespace Aws::Crt;
using namespace Aws::Crt::Mqtt5;

struct app_ctx
{
    struct aws_allocator *allocator;
    Io::Uri uri;
    uint16_t port;
    const char *cacert;
    const char *cert;
    const char *key;
    int connect_timeout;

    struct aws_tls_connection_options tls_connection_options;

    const char *TraceFile;
    Aws::Crt::LogLevel LogLevel;
};

static void s_usage(int exit_code)
{

    fprintf(stderr, "usage: websocket_app [options] endpoint\n");
    fprintf(stderr, " endpoint: url to connect to\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(stderr, "      --cacert FILE: path to a CA certficate file.\n");
    fprintf(stderr, "      --cert FILE: path to a PEM encoded certificate to use with mTLS\n");
    fprintf(stderr, "      --key FILE: Path to a PEM encoded private key that matches cert.\n");
    fprintf(stderr, "  -l, --log FILE: dumps logs to FILE instead of stderr.\n");
    fprintf(stderr, "  -v, --verbose: ERROR|INFO|DEBUG|TRACE: log level to configure. Default is none.\n");

    fprintf(stderr, "  -h, --help\n");
    fprintf(stderr, "            Display this message and quit.\n");
    exit(exit_code);
}

static struct aws_cli_option s_long_options[] = {
    {"cacert", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'a'},
    {"cert", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'c'},
    {"key", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'e'},
    {"connect-timeout", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'f'},
    {"log", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'l'},
    {"verbose", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'v'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    /* Per getopt(3) the last element of the array has to be filled with all zeros */
    {NULL, AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 0},
};

static void s_parse_options(int argc, char **argv, struct app_ctx &ctx)
{
    while (true)
    {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "a:b:c:e:f:H:d:g:M:GPHiko:t:l:v:VwWh", s_long_options, &option_index);
        if (c == -1)
        {
            /* finished parsing */
            break;
        }

        switch (c)
        {
            case 0:
                /* getopt_long() returns 0 if an option.flag is non-null */
                break;
            case 0x02:
                /* getopt_long() returns 0x02 (START_OF_TEXT) if a positional arg was encountered */
                ctx.uri = Io::Uri(aws_byte_cursor_from_c_str(aws_cli_positional_arg), ctx.allocator);
                if (!ctx.uri)
                {
                    std::cerr << "Failed to parse uri \"" << aws_cli_positional_arg << "\" with error "
                              << aws_error_debug_str(ctx.uri.LastError()) << std::endl;
                    s_usage(1);
                }
                else
                {
                    std::cerr << "Success to parse uri \"" << aws_cli_positional_arg
                              << static_cast<const char *>(AWS_BYTE_CURSOR_PRI(ctx.uri.GetFullUri())) << std::endl;
                }
                break;
            case 'a':
                ctx.cacert = aws_cli_optarg;
                break;
            case 'c':
                ctx.cert = aws_cli_optarg;
                break;
            case 'e':
                ctx.key = aws_cli_optarg;
                break;
            case 'l':
                ctx.TraceFile = aws_cli_optarg;
                break;
            case 'h':
                s_usage(0);
                break;
            case 'v':
            {
                enum aws_log_level temp_log_level = AWS_LL_NONE;
                aws_string_to_log_level(aws_cli_optarg, &temp_log_level);
                ctx.LogLevel = (Aws::Crt::LogLevel)temp_log_level;
                if (ctx.LogLevel < Aws::Crt::LogLevel::Error)
                {
                    std::cerr << "unsupported log level " << aws_cli_optarg << std::endl;
                    s_usage(1);
                }
                break;
            }
            default:
                std::cerr << "Unknown option\n";
                s_usage(1);
        }
    }

    if (!ctx.uri)
    {
        std::cerr << "A URI for the request must be supplied.\n";
        s_usage(1);
    }
}

uint16_t receive_maximum = 9;
uint32_t maximum_packet_size = 128 * 1024;

/**********************************************************
 * MAIN
 **********************************************************/

/**
 * This is a sample to show basic functionality for the mqtt5 clients.
 * The app will demo connect/subscribe/publish/unsubscribe features, and
 * requires user interaction.
 * Please follow the instructions when [ACTION REQUIRED] pop up.
 *
 * The workflow for the application will be
 *  1. connect to server
 *  2. subscribe to topic "test/topic/test1", "test/topic/test2", and
 * "test/topic/test3"
 *  3. publish message "mqtt5 publish test"
 *  4. waiting for message from user for "test/topic/test1" and "test/topic/test2"
 *     to make sure the subscription succeed.
 *  5. unsubscribe from "test/topic/test1" and "test/topic/test2". Then make sure
 *     we are no longer subscribe to the topics.
 *  6. waiting for message from user for "test/topic/test3" to make sure we are still
 *     subscribing to "test/topic/test3"
 */

int main(int argc, char **argv)
{

    struct aws_allocator *allocator = aws_mem_tracer_new(aws_default_allocator(), NULL, AWS_MEMTRACE_STACKS, 15);

    struct app_ctx app_ctx = {};
    app_ctx.allocator = allocator;
    app_ctx.connect_timeout = 3000;
    app_ctx.port = 443;

    s_parse_options(argc, argv, app_ctx);
    if (app_ctx.uri.GetPort())
    {
        app_ctx.port = app_ctx.uri.GetPort();
    }

    // s_aws_mqtt5_canary_update_tps_sleep_time(&tester_options);
    // s_aws_mqtt5_canary_init_weighted_operations(&tester_options);

    /**********************************************************
     * LOGGING
     **********************************************************/

    ApiHandle apiHandle(allocator);
    if (app_ctx.TraceFile)
    {
        apiHandle.InitializeLogging(app_ctx.LogLevel, app_ctx.TraceFile);
    }
    else
    {
        apiHandle.InitializeLogging(app_ctx.LogLevel, stdout);
    }

    auto hostName = app_ctx.uri.GetHostName();
    Aws::Iot::MqttClient mqttClient;
    Aws::Iot::MqttClientConnectionConfigBuilder clientConfigBuilder;

    std::shared_ptr<Aws::Crt::Auth::ICredentialsProvider> provider = nullptr;

    Aws::Crt::Auth::CredentialsProviderChainDefaultConfig defaultConfig;
    provider = Aws::Crt::Auth::CredentialsProvider::CreateCredentialsProviderChainDefault(defaultConfig);

    if (!provider)
    {
        fprintf(stderr, "Failure to create credentials provider!\n");
        exit(-1);
    }

    Aws::Iot::WebsocketConfig config("us-east-1", provider);
    clientConfigBuilder = Aws::Iot::MqttClientConnectionConfigBuilder(config);

    clientConfigBuilder.WithCertificateAuthority(app_ctx.cacert);

    clientConfigBuilder.WithEndpoint(Aws::Crt::String((char*)hostName.ptr, hostName.len));

    auto clientConfig = clientConfigBuilder.Build();
    if (!clientConfig)
    {
        fprintf(
            stderr,
            "Client Configuration initialization failed with error %s\n",
            Aws::Crt::ErrorDebugString(clientConfig.LastError()));
        exit(-1);
    }

    auto connection = mqttClient.NewConnection(clientConfig);
    if (!*connection)
    {
        fprintf(
            stderr,
            "MQTT Connection Creation failed with error %s\n",
            Aws::Crt::ErrorDebugString(connection->LastError()));
        exit(-1);
    }

    // Get the client ID to send with the connection
    String clientId = String("test-") + Aws::Crt::UUID().ToString();

    /*
        * In a real world application you probably don't want to enforce synchronous behavior
        * but this is a sample console application, so we'll just do that with a condition variable.
        */
    std::promise<bool> connectionCompletedPromise;
    std::promise<void> connectionClosedPromise;

    /*
        * This will execute when an mqtt connect has completed or failed.
        */
    auto onConnectionCompleted =
        [&](Aws::Crt::Mqtt::MqttConnection &, int errorCode, Aws::Crt::Mqtt::ReturnCode returnCode, bool) {
            if (errorCode)
            {
                fprintf(stdout, "Connection failed with error %s\n", Aws::Crt::ErrorDebugString(errorCode));
                connectionCompletedPromise.set_value(false);
            }
            else
            {
                fprintf(stdout, "Connection completed with return code %d\n", returnCode);
                connectionCompletedPromise.set_value(true);
            }
        };

    auto onInterrupted = [&](Aws::Crt::Mqtt::MqttConnection &, int error) {
        uint64_t timestamp = 0;
        aws_high_res_clock_get_ticks(&timestamp);
        fprintf(stdout, "Connection interrupted with error %s, %llu\n", Aws::Crt::ErrorDebugString(error), timestamp);
    };
    auto onResumed = [&](Aws::Crt::Mqtt::MqttConnection &, Aws::Crt::Mqtt::ReturnCode, bool) {
        uint64_t timestamp = 0;
        aws_high_res_clock_get_ticks(&timestamp);
        fprintf(stdout, "Connection resumed: %llu\n", timestamp);
    };

    connection->OnConnectionCompleted = std::move(onConnectionCompleted);
    connection->OnConnectionInterrupted = std::move(onInterrupted);
    connection->OnConnectionResumed = std::move(onResumed);

    /*
        * Actually perform the connect dance.
        */
    fprintf(stdout, "Connecting...\n");
    if (!connection->Connect(clientId.c_str(), false /*cleanSession*/, 1000 /*keepAliveTimeSecs*/))
    {
        fprintf(
            stderr, "MQTT Connection failed with error %s\n", Aws::Crt::ErrorDebugString(connection->LastError()));
        exit(-1);
    }

    // wait for the OnConnectionCompleted callback to fire, which sets connectionCompletedPromise...
    if (connectionCompletedPromise.get_future().get() == false)
    {
        fprintf(stderr, "Connection failed\n");
        exit(-1);
    }
    // Well, we just keep the client running...
}

