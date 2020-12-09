#include <iostream>
#include <cstring>
#include <string>
#include <fstream>
#include <stdlib.h>
#include <experimental/filesystem>

int apache[59], nginx[36], docker[17], apiserver[33], controler_manager[7], scheduler[2], etcd[7], conf[12];
namespace fs = std::experimental::filesystem;
using namespace std;

void mass_update() {
    for (int i = 0; i < 59; i++) {
        apache[i] = 0;
        if (i < 36)
            nginx[i] = 0;
        if (i < 17)
            docker[i] = 0;
        if (i < 33)
            apiserver[i] = 0;
        if (i < 12)
            conf[i] = 0;
        if (i < 7) {
            controler_manager[i] = 0;
            etcd[i] = 0;
        }
        if (i < 2)
            scheduler[i] = 0;
    }
    return;
}

int check(const char *file) {
    ifstream f(file);
    if ((strstr(file, ".yaml") == NULL) && (strstr(file, ".conf") == NULL) && (strstr(file, ".json") == NULL) &&
        (strstr(file, ".load") == NULL)) { return 1; }
    else {
        if (!f.is_open())
            return 2;
    }
    f.close();
    if (strstr(file, "apache2") != NULL)
        return 3;
    if (strstr(file, "httpd") != NULL)
        return 4;
    return 0;
}

void kube_conclude(int i) {
    if (i == 1) {
        if (apiserver[0] != 1)
            cout << "Error,anonymous-auth is enabled, check 1.2.1 CIS Benchmark" << endl;
        if (apiserver[1] == 1)
            cout << "Error,basik-auth-file is enabled, check 1.2.2 CIS Benchmark" << endl;
        if (apiserver[2] == 1)
            cout << "Error,token-auth-file is enabled, check 1.2.3 CIS Benchmark" << endl;
        if (apiserver[3] == 1)
            cout << "Error,kubelet-https is enabled, check 1.2.4 CIS Benchmark" << endl;
        if (apiserver[4] != 2)
            cout << "Error,no kubelet-client-certificate or kubelet-client-key, check 1.2.5 CIS Benchmark" << endl;
        if (apiserver[5] != 1)
            cout << "Error,no kubelet-certificate-authority, check 1.2.6 CIS Benchmark" << endl;
        if (apiserver[6] != 1)
            cout << "Error,no RBAC value for authorization-mode, check 1.2.7 CIS Benchmark" << endl;
        if (apiserver[7] != 1)
            cout << "Error,no Node value for authorization-mode, check 1.2.8 CIS Benchmark" << endl;
        if (apiserver[8] != 2)
            cout
                    << "Error,no EventRateLimit value for enable-admission-plugins or not set admission-control-config-file, check 1.2.10 CIS Benchmark"
                    << endl;
        if (apiserver[9] != 1)
            cout << "Error,AlwaysAdmit value for enable-admission-plugins, check 1.2.11 CIS Benchmark" << endl;
        if (apiserver[10] != 1)
            cout << "Error,no AlwaysPullImages value for enable-admission-plugins, check 1.2.12 CIS Benchmark" << endl;
        if (apiserver[11] != 1)
            cout << "Error,no SecurityContextDeny value for enable-admission-plugins, check 1.2.13 CIS Benchmark"
                 << endl;
        if (apiserver[12] != 1)
            cout << "Error,ServiceAccount value for disable-admission-plugins, check 1.2.14 CIS Benchmark" << endl;
        if (apiserver[13] != 1)
            cout << "Error,NamespaceLifecycle value for disable-admission-plugins, check 1.2.15 CIS Benchmark" << endl;
        if (apiserver[14] != 1)
            cout << "Error,no PodSecurityPolicy value for enable-admission-plugins, check 1.2.16 CIS Benchmark" << endl;
        if (apiserver[15] != 1)
            cout << "Error,no NodeRestriction value for enable-admission-plugins, check 1.2.17 CIS Benchmark" << endl;
        if (apiserver[16] == 1)
            cout << "Error,insecure-bind-address is enabled, check 1.2.18 CIS Benchmark" << endl;
        if (apiserver[17] != 1)
            cout << "Error,insecure-port is no 0, check 1.2.19 CIS Benchmark" << endl;
        if (apiserver[18] == 1)
            cout << "Error,secure-port have 0 value, check 1.2.20 CIS Benchmark" << endl;
        if (apiserver[19] != 1)
            cout << "Error,profiling is enabled, check 1.2.21 CIS Benchmark" << endl;
        if (apiserver[20] != 1)
            cout << "Error,no audit-log-path, check 1.2.22 CIS Benchmark" << endl;
        if (apiserver[21] != 1)
            cout << "Error,no audit-log-maxage, check 1.2.23 CIS Benchmark" << endl;
        if (apiserver[22] != 1)
            cout << "Error,no audit-log-maxbackup, check 1.2.24 CIS Benchmark" << endl;
        if (apiserver[23] != 1)
            cout << "Error,no audit-log-maxsize, check 1.2.25 CIS Benchmark" << endl;
        if (apiserver[24] != 1)
            cout << "Error,no request-timeout, check 1.2.26 CIS Benchmark" << endl;
        if (apiserver[25] != 1)
            cout << "Error,service-account-lookup is disabled, check 1.2.27 CIS Benchmark" << endl;
        if (apiserver[26] != 1)
            cout << "Error,no service-account-key-file, check 1.2.28 CIS Benchmark" << endl;
        if (apiserver[27] != 2)
            cout << "Error,no etcd-certfile or etcd-keyfile, check 1.2.29 CIS Benchmark" << endl;
        if (apiserver[28] != 2)
            cout << "Error,no tls-cert-file or tls-private-key-file, check 1.2.30 CIS Benchmark" << endl;
        if (apiserver[29] != 1)
            cout << "Error,no client-ca-file, check 1.2.31 CIS Benchmark" << endl;
        if (apiserver[30] != 1)
            cout << "Error,no etcd-ca-file, check 1.2.32 CIS Benchmark" << endl;
        if (apiserver[31] != 1)
            cout << "Error,no encryption-provider-config, check 1.2.33 CIS Benchmark" << endl;
        if (apiserver[32] != 1)
            cout << "Error,no tls-cipher, check 1.2.35 CIS Benchmark" << endl;
    }
    if (i == 2) {
        if (controler_manager[0] != 1)
            cout << "Error,no terminated-pod-gc-threshold, check 1.3.1 CIS Benchmark" << endl;
        if (controler_manager[1] != 1)
            cout << "Error,profiling is enabled, check 1.3.2 CIS Benchmark" << endl;
        if (controler_manager[2] != 1)
            cout << "Error,use-service-account-credentials is disabled, check 1.3.3 CIS Benchmark" << endl;
        if (controler_manager[3] != 1)
            cout << "Error,no service-account-private-key-file, check 1.3.4 CIS Benchmark" << endl;
        if (controler_manager[4] != 1)
            cout << "Error,no root-ca-file, check 1.3.5 CIS Benchmark" << endl;
        if (controler_manager[5] != 1)
            cout << "Error,feature-gates=RotateKubeletServerCertificate is disabled, check 1.3.6 CIS Benchmark" << endl;
        if (controler_manager[6] != 1)
            cout << "Error,no bind-address, check 1.3.7 CIS Benchmark" << endl;
    }
    if (i == 3) {
        if (scheduler[0] != 1)
            cout << "Error,profiling is enabled, check 1.4.1 CIS Benchmark" << endl;
        if (scheduler[1] != 1)
            cout << "Error,no bind-address, check 1.4.2 CIS Benchmark" << endl;
    }
    if (i == 4) {
        if (etcd[0] != 2)
            cout << "Error,no cert-file or key-file, check 2.1 CIS Benchmark" << endl;
        if (etcd[1] != 1)
            cout << "Error,client-cert-auth is disabled, check 2.2 CIS Benchmark" << endl;
        if (etcd[2] == 1)
            cout << "Error,auto-tls is enabled, check 2.3 CIS Benchmark" << endl;
        if (etcd[3] != 2)
            cout << "Error,no peer-client-file or peer-key-file, check 2.4 CIS Benchmark" << endl;
        if (etcd[4] != 1)
            cout << "Error,peer-client-cert-auth is disabled, check 2.5 CIS Benchmark" << endl;
        if (etcd[5] == 1)
            cout << "Error,peer-auto-tls is enabled, check 2.6 CIS Benchmark" << endl;
        if (etcd[6] != 1)
            cout << "Error,no trusted-ca-file, check 2.7 CIS Benchmark" << endl;
    }
    if (i == 5) {
        if (conf[0] != 1)
            cout << "Error,anonymous-auth is enabled, check 4.2.1 CIS Benchmark" << endl;
        if (conf[1] != 1)
            cout << "Error,bad value for authorization-mode, check 4.2.2 CIS Benchmark" << endl;
        if (conf[2] != 1)
            cout << "Error,no client-ca-file, check 4.2.3 CIS Benchmark" << endl;
        if (conf[3] != 1)
            cout << "Error,bad value for read-only-port, check 4.2.4 CIS Benchmark" << endl;
        if (conf[4] != 1)
            cout << "Error,bad value for streaming-connection-idle-timeout, check 4.2.5 CIS Benchmark" << endl;
        if (conf[5] != 1)
            cout << "Error,protect-kernel-defaults is disabled, check 4.2.6 CIS Benchmark" << endl;
        if (conf[6] == 1)
            cout << "Error,no make-iptables-util-chains, check 4.2.7 CIS Benchmark" << endl;
        if (conf[7] == 1)
            cout << "Error,no hostname-override, check 4.2.8 CIS Benchmark" << endl;
        if (conf[8] != 2)
            cout << "Error,no tls-cert-file or tls-private-key-file, check 4.2.10 CIS Benchmark" << endl;
        if (conf[9] == 1)
            cout << "Error,rotate-certificates= is enabled, check 4.2.11 CIS Benchmark" << endl;
        if (conf[10] != 1)
            cout << "Error,feature-gates=RotateKubeletServerCertificate is disabled, check 4.2.12 CIS Benchmark"
                 << endl;
        if (conf[11] != 1)
            cout << "Error,no tls-cipher-suites, check 4.2.13 CIS Benchmark" << endl;
    }
    if (i == 0) {
        cout << "File not for this programm" << endl;
    }
    return;
}

void docker_conclude() {
    if (docker[0] != 1)
        cout << "Error, icc is enabled, check 2.1 CIS Benchmark" << endl;
    if (docker[1] != 1)
        cout << "Error, bad log-level value, check 2.2 CIS Benchmark" << endl;
    if (docker[2] != 1)
        cout << "Error, iptables is enabled, check 2.3 CIS Benchmark" << endl;
    if (docker[3] != 0)
        cout << "Error, insecure registries, check 2.4 CIS Benchmark" << endl;
    if (docker[4] != 0)
        cout << "Error, storage-driver are aufs, check 2.5 CIS Benchmark" << endl;
    if (docker[5] != 4)
        cout << "Error, no tls parameters, check 2.6 CIS Benchmark" << endl;
    if (docker[6] != 2)
        cout << "Error, no nproc or nofile parameters for default-ulimit, check 2.7 CIS Benchmark" << endl;
    if (docker[7] != 1)
        cout << "Error, bad value for userns-remap, check 2.8 CIS Benchmark" << endl;
    if (docker[8] != 1)
        cout << "Error, no cgroup-parent paremeter, check 2.9 CIS Benchmark" << endl;
    if (docker[9] != 0)
        cout << "Error, storage-opt is dm.basesize , check 2.10 CIS Benchmark" << endl;
    if (docker[10] != 1)
        cout << "Error, no autarisation_plugin, check 2.11 CIS Benchmark" << endl;
    if (docker[11] != 2)
        cout << "Error, no log-driver syslog value or log-opt paremeter, check 2.12 CIS Benchmark" << endl;
    if (docker[12] != 1)
        cout << "Error, live-restore is disabled, check 2.13 CIS Benchmark" << endl;
    if (docker[13] != 1)
        cout << "Error, userland-proxy is enabled, check 2.14 CIS Benchmark" << endl;
    if (docker[14] != 1)
        cout << "Error, no seccomp-profile paremeter, check 2.15 CIS Benchmark" << endl;
    if (docker[15] != 0)
        cout << "Error, experimental is enabled, check 2.16 CIS Benchmark" << endl;
    if (docker[16] != 1)
        cout << "Error, no-new-privileges is disabled, check 2.17 CIS Benchmark" << endl;
}

void nginx_conclude() {
    if (nginx[0] != 1)
        cout << "Error, no listen or server_name, check 2.4.2 CIS Benchmark" << endl;
    if (nginx[1] != 1)
        cout << "Error, keepalive_timeout value more then 10 or 0, check 2.4.3 CIS Benchmark" << endl;
    if (nginx[2] != 1)
        cout << "Error, send_timeout value more then 10 or 0, check 2.4.4 CIS Benchmark" << endl;
    if (nginx[3] != 1)
        cout << "Error, server_tokens is on, check 2.5.1 CIS Benchmark" << endl;
    if (nginx[4] != 2)
        cout << "Error, no location ~/\\, check 2.5.3 CIS Benchmark" << endl;
    if (nginx[5] != 2)
        cout << "Error, no X-Powered-By and Server headers, check 2.5.4 CIS Benchmark" << endl;
    if (nginx[6] != 1)
        cout << "Error, no value for access_log, check 3.2 CIS Benchmark" << endl;
    if (nginx[7] != 1)
        cout << "Error, no value for error_log, check 3.3 CIS Benchmark" << endl;
    if (nginx[8] != 1)
        cout << "Error, no syslog value for error_log, check 3.5 CIS Benchmark" << endl;
    if (nginx[9] != 1)
        cout << "Error, no syslog value for access_log , check 3.6 CIS Benchmark" << endl;
    if (nginx[10] != 3)
        cout << "Error, no X-Real-IP and X-Forwarded-For headers, check 3.7 CIS Benchmark" << endl;
    if (nginx[11] != 1)
        cout << "Error, no redirection for https, check 4.1.1 CIS Benchmark" << endl;
    if (nginx[12] != 3)
        cout << "Error, no ssl parameters, check 4.1.2 CIS Benchmark" << endl;
    if (nginx[13] != 2)
        cout << "Error, no ssl_protocols, check 4.1.4 CIS Benchmark" << endl;
    if (nginx[14] != 2)
        cout << "Error, no ssl_ciphers, check 4.1.5 CIS Benchmark" << endl;
    if (nginx[15] != 1)
        cout << "Error, no ssl_dhparam, check 4.1.6 CIS Benchmark" << endl;
    if (nginx[16] != 2)
        cout << "Error, no ssl_stapling, check 4.1.7 CIS Benchmark" << endl;
    if (nginx[17] != 1)
        cout << "Error, no Strict-Transport-Security header, check 4.1.8 CIS Benchmark" << endl;
    if (nginx[18] != 1)
        cout << "Error, no Public-Key-Pins header, check 4.1.9 CIS Benchmark" << endl;
    if (nginx[19] != 2)
        cout << "Error, no proxy_ssl parameters, check 4.1.10 CIS Benchmark" << endl;
    if (nginx[20] != 2)
        cout << "Error, no proxy_ssl_verify or proxy_ssl_trusted_certificate, check 4.1.11 CIS Benchmark" << endl;
    if (nginx[21] != 1)
        cout << "Error, no Strict-Transport-Security header, check 4.1.12 CIS Benchmark" << endl;
    if (nginx[22] != 1)
        cout << "Error, ssl_session_tickets is on, check 4.1.13 CIS Benchmark" << endl;
    if (nginx[23] != 1)
        cout << "Error, no http2 value for listen, check 4.1.14 CIS Benchmark" << endl;
    if (nginx[24] != 2)
        cout << "Error, no values allow or deny in root location, check 5.1.1 CIS Benchmark" << endl;
    if (nginx[25] != 1)
        cout << "Error, no condition for CET|HGEAD|POST, check 5.1.2 CIS Benchmark" << endl;
    if (nginx[26] != 2)
        cout << "Error, no client_body_timeout or client_header_timeout, check 5.2.1 CIS Benchmark" << endl;
    if (nginx[27] != 1)
        cout << "Error, no client_max_header_buffers, check 5.2.2 CIS Benchmark" << endl;
    if (nginx[28] != 1)
        cout << "Error, no large_client_header_buffers, check 5.2.3 CIS Benchmark" << endl;
    if (nginx[29] != 2)
        cout << "Error, no limit_conn_zone or limit_conn, check 5.2.4 CIS Benchmark" << endl;
    if (nginx[30] != 2)
        cout << "Error, no limit_req_zoe or limit_req, check 5.2.5 CIS Benchmark" << endl;
    if (nginx[31] != 1)
        cout << "Error, no X-Frame-Options header, check 5.3.1 CIS Benchmark" << endl;
    if (nginx[32] != 1)
        cout << "Error, no X-Content-Type-Options header, check 5.3.2 CIS Benchmark" << endl;
    if (nginx[33] != 1)
        cout << "Error, no X-Xss-Protection header, check 5.3.3 CIS Benchmark" << endl;
    if (nginx[34] != 1)
        cout << "Error, no Content-Security-Policy header, check 5.3.4 CIS Benchmark" << endl;
    if (nginx[35] != 1)
        cout << "Error, no Referrer-Policy header, check 5.3.5 CIS Benchmark" << endl;
}

void apache_conclude() {
    if (apache[0] != 1)
        cout << "Error, don't load log_config_module, check 2.2 CIS Benchmark" << endl;
    if (apache[1] != 0)
        cout << "Error, load dav modules, check 2.3 CIS Benchmark" << endl;
    if (apache[2] != 0)
        cout << "Error, load states_module, check 2.4 CIS Benchmark" << endl;
    if (apache[3] != 0)
        cout << "Error, load autoindex_module, check 2.5 CIS Benchmark" << endl;
    if (apache[4] != 0)
        cout << "Error, load proxy modules, check 2.6 CIS Benchmark" << endl;
    if (apache[5] != 0)
        cout << "Error, load userdir_module, check 2.7 CIS Benchmark" << endl;
    if (apache[6] != 0)
        cout << "Error, load info_module, check 2.8 CIS Benchmark" << endl;
    if (apache[7] != 0)
        cout << "Error, load mod_auth_basik or mod_auth_digest, check 2.9 CIS Benchmark" << endl;
    if (apache[8] != 2)
        cout << "Error, bad value for User of Group, check 3.1 CIS Benchmark" << endl;
    if (apache[9] != 1)
        cout << "Error, no Require all denied in root directory, check 4.1 CIS Benchmark" << endl;
    if (apache[10] != 1)
        cout << "Error, no Require all denied in directories and locations, check 4.2 CIS Benchmark" << endl;
    if (apache[11] != 1)
        cout << "Error, no AllowOverride None in root direcroty, check 4.3 CIS Benchmark" << endl;
    if (apache[12] != 1)
        cout << "Error, no AllowOverride None in directories and locations, check 4.4 CIS Benchmark" << endl;
    if (apache[13] != 1)
        cout << "Error, no Options None in root direcroty, check 5.1 CIS Benchmark" << endl;
    if (apache[14] != 1)
        cout << "Error, no Options None in root web direcroty, check 5.2 CIS Benchmark" << endl;
    if (apache[15] != 1)
        cout << "Error, no Options in direcroties include \"Include\", check 5.3 CIS Benchmark" << endl;
    if (apache[16] != 1)
        cout << "Error, no proxy condition or include exampe.conf file, check 5.4 CIS Benchmark" << endl;
    if (apache[17] != 1)
        cout << "Error, no Require all dinied option in LimitExceot part of every directory, check 5.7 CIS Benchmark"
             << endl;
    if (apache[18] != 1)
        cout << "Error, TraceEnable opion is on, check 5.8 CIS Benchmark" << endl;
    if (apache[19] != 3)
        cout << "Error, no values for RewriteEngine or RewriteCond or RewriteRule,check 5.9 CIS Benchmark" << endl;
    if (apache[20] != 1)
        cout << "Error, no Require all denied options for ht files, check 5.10 CIS Benchmark" << endl;
    if (apache[21] != 2)
        cout
                << "Error, no Require all denied options for *$ files of Reuire all gatanted for special files, check 5.11 CIS Benchmark"
                << endl;
    if (apache[22] != 2)
        cout << "Error, no special RewriteCond and RewriteRule, check 5.12 CIS Benchmark" << endl;
    if (apache[23] != 1)
        cout << "Error, no Listen option, check 5.13 CIS Benchmark" << endl;
    if (apache[24] != 1)
        cout << "Error, bad value for X-Frame-Options header, check 5.14 CIS Benchmark" << endl;
    if (apache[25] != 2)
        cout << "Error, no LogLevel and EllorLog, check 6.1 CIS Benchmark" << endl;
    if (apache[26] != 1)
        cout << "Error, no syslog value for ErrorLog, check 6.2 CIS Benchmark" << endl;
    if (apache[27] != 2)
        cout << "Error, no LogFormat or CustomLog valuse, check 6.3 CIS Benchmark" << endl;
    if (apache[28] != 1)
        cout << "Error, don't load security2_module, chech 6.6 CIS Benchmark" << endl;
    if (apache[29] != 3)
        cout
                << "Error, no SSLCertificateFali or SSLCertificateKeyFile or SSLCertificateChainFile, check 7.2 CIS Benchmark"
                << endl;
    if (apache[30] != 1)
        cout << "Error, no SSLProtocol, check 7.4 CIS Benchmark" << endl;
    if (apache[31] != 2)
        cout << "Error, no SSLHonorCipherOrder or SSLCipherSuite, check 7.5 CIS Benchmark" << endl;
    if (apache[32] != 1)
        cout << "Error, no SSLInsecureRenegotation off, check 7.6 CIS Benchmark" << endl;
    if (apache[33] != 1)
        cout << "Error, no SSLCompression off, check 7.7 CIS Benchmark" << endl;
    if (apache[34] != 2)
        cout << "Error, no SSLHonorCipherOrder or SSLCipherSuite for every VirhualHost, check 7.8 CIS Benchmark"
             << endl;
    if (apache[35] != 1)
        cout << "Error, no Redirect permanent https value, check 7.9 CIS Benchmark" << endl;
    if (apache[36] != 2)
        cout << "Error, no SSLUserStapling On or SSLStaplingCache, check 7.11 CIS Benchmark" << endl;
    if (apache[37] != 1)
        cout << "Error, bad value for Strict-Transport-Security header, check 7.12 CIS Benchmark" << endl;
    if (apache[38] != 1)
        cout << "Error, bad value for SSLCipherSuite, check 7.13 CIS Benchmark" << endl;
    if (apache[39] != 1)
        cout << "Error, no ServerTokens Prod, check 8.1 CIS Benchmark" << endl;
    if (apache[40] != 1)
        cout << "Error, no ServerSignature Off, check 8.2 CIS Benchmark" << endl;
    if (apache[41] != 1)
        cout << "Error, bad value for FileETag, check 8.4 CIS Benchmark" << endl;
    if (apache[42] != 1)
        cout << "Error, bad value for Timeout, check 9.1 CIS Benchmark" << endl;
    if (apache[43] != 1)
        cout << "Error, KeepAlive off, check 9.2 CIS Benchmark" << endl;
    if (apache[44] != 1)
        cout << "Error, bad value for MaxKeepAliveRequests, check 9.3 CIS Benchmark" << endl;
    if (apache[45] != 1)
        cout << "Error, bad value for KeepAliveTimeout, check 9.4 CIS Benchmark" << endl;
    if (apache[46] != 1)
        cout << "Error, bad value for header option in RequestReadTimeout, check 9.5 CIS Benchmark" << endl;
    if (apache[47] != 1)
        cout << "Error, bad value for body option in RequestReadTimeout, check 9.6 CIS Benchmark" << endl;
    if (apache[48] != 1)
        cout << "Error, bad value for LimitRequestLine, check 10.1 CIS Benchmark" << endl;
    if (apache[49] != 1)
        cout << "Error, bad value for LimitRequestFields, check 10.2 CIS Benchmark" << endl;
    if (apache[50] != 1)
        cout << "Error, bad value for LimitRequestFieldsize, check 10.3 CIS Benchmark" << endl;
    if (apache[51] != 1)
        cout << "Error, bad value for LimitRequestBody, check 10.4 CIS Benchmark" << endl;
    if (apache[52] != 1)
        cout << "Error, bad value for LimitXMLRequestBody, try to set it <= 1048576" << endl;
    if (apache[53] != 1)
        cout << "Error, bad value for Set-Cookie header, try to set it ^(.*)$ $1;HttpOnly;Secure" << endl;
    if (apache[54] != 1)
        cout << "Error, bad value for X-XSS-Protection header, try to set it \"1; mode=block\"" << endl;
    if (apache[55] != 1)
        cout << "Error, no SecAuditLog" << endl;
    if (apache[56] != 1)
        cout << "Error, SecRuleEngine is off" << endl;
    if (apache[57] != 1)
        cout << "Error, no SecServerSignature" << endl;
    if (apache[58] != 1)
        cout << "Error, bad value for Deny, try to set it from all" << endl;
}

int kube_func(const char *file) {
    switch (check(file)) {
        case 1:
            return -1;
        case 2:
            return -1;
    }
    ifstream f;
    f.open(file, ios_base::in | ios_base::binary);
    string s;
    int k = 0;
    while (!f.eof()) {
        getline(f, s);
        k++;
    }
    f.clear();
    f.seekg(0, ios_base::beg);
    string *mas = new string[k];
    int i = 0;
    while (!f.eof()) {
        getline(f, s);
        mas[i] = s;
        i++;
    }
    f.close();
    if (strstr(file, "kube-apiserver.yaml") != NULL) {
        for (i = 0; i < k; i++) {
            if ((mas[i].find("--anonymous-auth=") != -1) && (mas[i].find("false") != -1))
                apiserver[0] = 1;
            if (mas[i].find("--basic-auth-file") != -1)
                apiserver[1] = 1;
            if (mas[i].find("--token-auth-file") != -1)
                apiserver[2] = 1;
            if (mas[i].find("--kubelet-https") != -1)
                apiserver[3] = 1;
            if (mas[i].find("--kubelet-client-certificate") != -1)
                apiserver[4] += 1;
            if (mas[i].find("--kubelet-client-key") != -1)
                apiserver[4] += 1;
            if (mas[i].find("--kubelet-certificate-authority") != -1)
                apiserver[5] = 1;
            if ((mas[i].find("--authorization-mode=") != -1) && (mas[i].find("RBAC") != -1))
                apiserver[6] = 1;
            if ((mas[i].find("--authorization-mode=") != -1) && (mas[i].find("Node") != -1))
                apiserver[7] = 1;
            if ((mas[i].find("--enable-admission-plugins=") != -1) && (mas[i].find("EventRateLimit") != -1))
                apiserver[8] += 1;
            if (mas[i].find("--admission-control-config-file") != -1)
                apiserver[8] += 1;
            if ((mas[i].find("--enable-admission-plugins=") != -1) && (mas[i].find("AlwaysAdmit") == -1))
                apiserver[9] = 1;
            if ((mas[i].find("--enable-admission-plugins=") != -1) && (mas[i].find("AlwaysPullImages") != -1))
                apiserver[10] = 1;
            if ((mas[i].find("--enable-admission-plugins=") != -1) && (mas[i].find("SecurityContextDeny") != -1))
                apiserver[11] = 1;
            if ((mas[i].find("--disable-admission-plugin=") != -1) && (mas[i].find("ServiceAccount") == -1))
                apiserver[12] = 1;
            if ((mas[i].find("--disable-admission-plugin=") != -1) && (mas[i].find("NamespaceLifecycle") == -1))
                apiserver[13] = 1;
            if ((mas[i].find("--enable-admission-plugins=") != -1) && (mas[i].find("PodSecurityPolicy") != -1))
                apiserver[14] = 1;
            if ((mas[i].find("--enable-admission-plugins=") != -1) && (mas[i].find("NodeRestriction") != -1))
                apiserver[15] = 1;
            if (mas[i].find("--insecure-bind-address") != -1)
                apiserver[16] = 1;
            if (mas[i].find("--insecure-port=0") != -1)
                apiserver[17] = 1;
            if (mas[i].find("--secure-port=0") != -1)
                apiserver[18] = 1;
            if ((mas[i].find("--profiling=") != -1) && (mas[i].find("false") != -1))
                apiserver[19] = 1;
            if (mas[i].find("--audit-log-path") != -1)
                apiserver[20] = 1;
            if (mas[i].find("--audit-log-maxage") != -1)
                apiserver[21] = 1;
            if (mas[i].find("--audit-log-maxbackup") != -1)
                apiserver[22] = 1;
            if (mas[i].find("--audit-log-maxsize") != -1)
                apiserver[23] = 1;
            if (mas[i].find("--request-timeout") != -1)
                apiserver[24] = 1;
            if ((mas[i].find("--service-account-lookup=") != -1) && (mas[i].find("true") != -1))
                apiserver[25] = 1;
            if (mas[i].find("--service-account-key-file") != -1)
                apiserver[26] = 1;
            if (mas[i].find("--etcd-certfile") != -1)
                apiserver[27] += 1;
            if (mas[i].find("--etcd-keyfile") != -1)
                apiserver[27] += 1;
            if (mas[i].find("--tls-cert-file") != -1)
                apiserver[28] += 1;
            if (mas[i].find("--tls-private-key-file") != -1)
                apiserver[28] += 1;
            if (mas[i].find("--client-ca-file") != -1)
                apiserver[29] = 1;
            if (mas[i].find("--etcd-ca-file") != -1)
                apiserver[30] = 1;
            if (mas[i].find("--encryption-provider-config") != -1)
                apiserver[31] = 1;
            if (mas[i].find("--tls-cipher") != -1)
                apiserver[32] = 1;
        }
        return 1;
    }
    if (strstr(file, "kube-controller-manager.yaml") != NULL) {
        for (i = 0; i < k; i++) {
            if (mas[i].find("--terminated-pod-gc-threshold") != -1)
                controler_manager[0] = 1;
            if ((mas[i].find("--profiling=") != -1) && (mas[i].find("false") != -1))
                controler_manager[1] = 1;
            if ((mas[i].find("--use-service-account-credentials=") != -1) && (mas[i].find("true") != -1))
                controler_manager[2] = 1;
            if (mas[i].find("--service-account-private-key-file") != -1)
                controler_manager[3] = 1;
            if (mas[i].find("--root-ca-file") != -1)
                controler_manager[4] = 1;
            if ((mas[i].find("--feature-gates=RotateKubeletServerCertificate=") != -1) && (mas[i].find("true") != -1))
                controler_manager[5] = 1;
            if (mas[i].find("--bind-address") != -1)
                controler_manager[6] = 1;
        }
        return 2;
    }
    if (strstr(file, "kube-scheduler.yaml") != NULL) {
        for (i = 0; i < k; i++) {
            if ((mas[i].find("--profiling=") != -1) && (mas[i].find("false") != -1))
                scheduler[0] = 1;
            if (mas[i].find("--bind-address") != -1)
                scheduler[1] = 1;
        }
        return 3;
    }
    if (strstr(file, "etcd.yaml") != NULL) {
        for (i = 0; i < k; i++) {
            if (mas[i].find("--cert-file") != -1)
                etcd[0] += 1;
            if (mas[i].find("--key-file") != -1)
                etcd[0] += 1;
            if ((mas[i].find("--client-cert-auth=") != -1) && (mas[i].find("true") != -1))
                etcd[1] = 1;
            if (mas[i].find("--auto-tls=") != -1)
                if (mas[i].find("false") == -1)
                    etcd[2] = 1;
            if (mas[i].find("--peer-client-file") != -1)
                etcd[3] += 1;
            if (mas[i].find("--peer-key-file") != -1)
                etcd[3] += 1;
            if ((mas[i].find("--peer-client-cert-auth=") != -1) && (mas[i].find("true") != -1))
                etcd[4] = 1;
            if (mas[i].find("--peer-auto-tls=") != -1)
                if (mas[i].find("false") == -1)
                    etcd[5] = 1;
            if (mas[i].find("--trusted-ca-file") != -1)
                etcd[6] = 1;
        }
        return 4;
    }
    if (strstr(file, "10-kubeadm.conf") != NULL) {
        for (i = 0; i < k; i++) {
            if ((mas[i].find("--anonymous-auth=") != -1) && (mas[i].find("false") != -1))
                conf[0] = 1;
            if ((mas[i].find("--authorization-mode=") != -1) && (mas[i].find("Webhook") != -1))
                conf[1] = 1;
            if (mas[i].find("--client-ca-file") != -1)
                conf[2] = 1;
            if (mas[i].find("--read-only-port=0") != -1)
                conf[3] = 1;
            if (mas[i].find("--streaming-connection-idle-timeout=5m") != -1)
                conf[4] = 1;
            if ((mas[i].find("--protect-kernel-defaults=") != -1) && (mas[i].find("true") != -1))
                conf[5] = 1;
            if (mas[i].find("--make-iptables-util-chains") != -1)
                conf[6] = 1;
            if (mas[i].find("--hostname-override") != -1)
                conf[7] = 1;
            if (mas[i].find("--tls-cert-file") != -1)
                conf[8] += 1;
            if (mas[i].find("--tls-private-key-file") != -1)
                conf[8] += 1;
            if ((mas[i].find("--rotate-certificates=") != -1) && (mas[i].find("false") != -1))
                conf[9] = 1;
            if ((mas[i].find("--feature-gates=RotateKubeletServerCertificate=") != -1) && (mas[i].find("true") != -1))
                conf[10] = 1;
            if (mas[i].find("--tls-cipher-suites") != -1)
                conf[11] = 1;
        }
        return 5;
    }
    return 0;
}

void docker_func(const char *file) {
    switch (check(file)) {
        case 1:
            return;
        case 2:
            return;
    }
    ifstream f;
    f.open(file, ios_base::in | ios_base::binary);
    string s;
    int k = 0;
    while (!f.eof()) {
        getline(f, s);
        k++;
    }
    f.clear();
    f.seekg(0, ios_base::beg);
    string *mas = new string[k];
    int i = 0;
    while (!f.eof()) {
        getline(f, s);
        mas[i] = s;
        i++;
    }
    f.close();
    for (i = 0; i < k; i++) {
        if ((mas[i].find("icc") != -1) && (mas[i].find("false") != -1))
            docker[0] = 1;
        if ((mas[i].find("log-level") != -1) && (mas[i].find("info") != -1))
            docker[1] = 1;
        if ((mas[i].find("iptables") != -1) && (mas[i].find("false") != -1))
            docker[2] = 1;
        if (mas[i].find("Insecure Registries") != -1)
            docker[3] = -1;
        if ((mas[i].find("storage-driver") != -1) && (mas[i].find("aufs") != -1))
            docker[4] = -1;
        if ((mas[i].find("tlsverify") != -1) && (mas[i].find("true") != -1))
            docker[5] += 1;
        if (mas[i].find("tlscacert") != -1)
            docker[5] += 1;
        if (mas[i].find("tlscert") != -1)
            docker[5] += 1;
        if (mas[i].find("tlskey") != -1)
            docker[5] += 1;
        if (mas[i].find("nofile") != -1)
            docker[6] += 0.5;
        if (mas[i].find("nproc") != -1)
            docker[6] += 0.5;
        if ((mas[i].find("userns-remap") != -1) && (mas[i].find("default") != -1))
            docker[7] = 1;
        if (mas[i].find("cgroup-parent") != -1)
            docker[8] = 1;
        if ((mas[i].find("storage-opt") != -1) && (mas[i].find("dm.basesize") != -1))
            docker[9] = -1;
        if (mas[i].find("authorization-plugin") != -1)
            docker[10] = 1;
        if ((mas[i].find("log-driver") != -1) && (mas[i].find("syslog") != -1))
            docker[11] += 1;
        if (mas[i].find("log-opt") != -1)
            docker[11] += 1;
        if ((mas[i].find("live-restore") != -1) && (mas[i].find("true") != -1))
            docker[12] = 1;
        if ((mas[i].find("userland-proxy") != -1) && (mas[i].find("false") != -1))
            docker[13] = 1;
        if (mas[i].find("seccomp-profile") != -1)
            docker[14] = 1;
        if ((mas[i].find("experimental") != -1) && (mas[i].find("false") == -1))
            docker[15] = -1;
        if ((mas[i].find("no-new-privileges") != -1) && (mas[i].find("true") != -1))
            docker[16] = 1;
    }
    return;
}

void nginx_func(const char *file) {
    switch (check(file)) {
        case 1:
            return;
        case 2:
            return;
    }
    ifstream f;
    f.open(file, ios_base::in | ios_base::binary);
    string s;
    int k = 0;
    while (!f.eof()) {
        getline(f, s);
        k++;
    }
    f.clear();
    f.seekg(0, ios_base::beg);
    string *mas = new string[k];
    int i = 0;
    while (!f.eof()) {
        getline(f, s);
        mas[i] = s;
        i++;
    }
    f.close();
    for (i = 0; i < k; i++) {
        if ((mas[i].find("listen ") != -1) && (mas[i].find("#") == -1)) {
            for (int j = 0; j < k; j++)
                if ((mas[i].find("server_name ") != -1) && (mas[i].find("#") == -1)) {
                    nginx[0] = 1;
                    break;
                }
        }
        if ((mas[i].find("keepalive_timeout ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, sizeof("keepalive_timeout"));
            s.erase(s.size() - 1);
            if ((atoi(s.c_str()) <= 10) && (atoi(s.c_str()) > 0))
                nginx[1] = 1;
        }
        if ((mas[i].find("send_timeout ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, sizeof("send_timeout"));
            s.erase(s.size() - 1);
            if ((atoi(s.c_str()) <= 10) && (atoi(s.c_str()) > 0))
                nginx[2] = 1;
        }
        if ((mas[i].find("server_tokens off") != -1) && (mas[i].find("#") == -1))
            nginx[3] = 1;
        if ((mas[i].find("location ~ /\\. {") != -1) && (mas[i].find("#") == -1))
            if (mas[i].find("location ~ /\\. {deny all; return 404;}") != -1)
                nginx[4] = 2;
            else {
                int j = i;
                do {
                    if ((mas[j].find("deny all") != -1) && (mas[j].find("#") == -1))
                        nginx[4] += 1;
                    if ((mas[j].find("return 404") != -1) && (mas[j].find("#") == -1))
                        nginx[4] += 1;
                    j++;
                } while (mas[j].find("}") == -1);
            }
        if ((mas[i].find("proxy_hide_header X-Powered-By") != -1) && (mas[i].find("#") == -1))
            nginx[5] += 1;
        if ((mas[i].find("proxy_hide_header Server") != -1) && (mas[i].find("#") == -1))
            nginx[5] += 1;
        if ((mas[i].find("access_log ") != -1) && (mas[i].find("syslog") == -1) && (mas[i].find("#") == -1))
            nginx[6] = 1;
        if ((mas[i].find("error_log ") != -1) && (mas[i].find("syslog") == -1) && (mas[i].find("#") == -1))
            nginx[7] = 1;
        if ((mas[i].find("access_log ") != -1) && (mas[i].find("syslog") != -1) && (mas[i].find("#") == -1))
            nginx[9] = 1;
        if ((mas[i].find("error_log ") != -1) && (mas[i].find("syslog") != -1) && (mas[i].find("#") == -1))
            nginx[8] = 1;
        if ((mas[i].find("proxy_pass ") != -1) && (mas[i].find("#") == -1))
            nginx[10] += 1;
        if ((mas[i].find("proxy_set_header X-Real-IP $remote_addr") != -1) && (mas[i].find("#") == -1))
            nginx[10] += 1;
        if ((mas[i].find("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for") != -1) &&
            (mas[i].find("#") == -1))
            nginx[10] += 1;
        if ((mas[i].find("return 301 https") != -1) && (mas[i].find("#") == -1))
            nginx[11] = 1;
        if ((mas[i].find("listen ") != -1) && (mas[i].find("ssl") != -1) && (mas[i].find("#") == -1))
            nginx[12] += 1;
        if ((mas[i].find("ssl_certificate ") != -1) && (mas[i].find("proxy") == -1) && (mas[i].find("#") == -1))
            nginx[12] += 1;
        if ((mas[i].find("ssl_certificate_key ") != -1) && (mas[i].find("proxy") == -1) && (mas[i].find("#") == -1))
            nginx[12] += 1;
        if ((mas[i].find("ssl_protocols TLSv1.2;") != -1) && (mas[i].find("proxy") == -1) && (mas[i].find("#") == -1))
            nginx[13] += 1;
        if ((mas[i].find("ssl_protocols TLSv1.2;") != -1) && (mas[i].find("proxy") != -1) && (mas[i].find("#") == -1))
            nginx[13] += 1;
        if ((mas[i].find("ssl_dhparam /etc/nginx/ssl/dhparam.pem") != -1) && (mas[i].find("#") == -1))
            nginx[15] = 1;
        if ((mas[i].find("ssl_stapling on") != -1) && (mas[i].find("#") == -1))
            nginx[16] += 1;
        if ((mas[i].find("ssl_stapling_verify on") != -1) && (mas[i].find("#") == -1))
            nginx[16] += 1;
        if ((mas[i].find("add_header Strict-Transport-Security \"max-age=15768000;\"") != -1) &&
            (mas[i].find("#") == -1))
            nginx[17] = 1;
        if ((mas[i].find("add_header Public-Key-Pins") != -1) && (mas[i].find("#") == -1))
            nginx[18] = 1;
        if ((mas[i].find("ssl_certificate ") != -1) && (mas[i].find("proxy") != -1) && (mas[i].find("#") == -1))
            nginx[19] += 1;
        if ((mas[i].find("ssl_certificate_key ") != -1) && (mas[i].find("proxy") != -1) && (mas[i].find("#") == -1))
            nginx[19] += 1;
        if ((mas[i].find("proxy_ssl_trusted_certificate ") != -1) && (mas[i].find("#") == -1))
            nginx[20] += 1;
        if ((mas[i].find("proxy_ssl_verify on") != -1) && (mas[i].find("#") == -1))
            nginx[20] += 1;
        if ((mas[i].find(
                "add_header Strict-Transport-Security \"Strict-Transport-Security: maxage=31536000; includeSubDomains; preload\"") !=
             -1) && (mas[i].find("#") == -1))
            nginx[21] = 1;
        if ((mas[i].find("ssl_session_tickets off") != -1) && (mas[i].find("#") == -1))
            nginx[22] = 1;
        if ((mas[i].find("listen ") != -1) && (mas[i].find("http2") != -1) && (mas[i].find("#") == -1))
            nginx[23] = 1;
        if ((mas[i].find("location / {") != -1) && (mas[i].find("#") == -1)) {
            int j = i;
            do {
                if ((mas[j].find("deny all") != -1) && (mas[j].find("#") == -1))
                    nginx[24] += 1;
                if ((mas[j].find("allow ") != -1) && (mas[j].find("#") == -1))
                    nginx[24] += 1;
                j++;
            } while (mas[j].find("}") == -1);
        }
        if ((mas[i].find("if ($request_method !~ ^(GET|HEAD|POST)$){") != -1) && (mas[i].find("#") == -1)) {
            int j = i;
            do {
                if ((mas[j].find("return 444") != -1) && (mas[j].find("#") == -1))
                    nginx[25] = 1;
                j++;
            } while (mas[j].find("}") == -1);
        }
        if ((mas[i].find("client_body_timeout ") != -1) && (mas[i].find("#") == -1))
            nginx[26] += 1;
        if ((mas[i].find("client_header_timeout ") != -1) && (mas[i].find("#") == -1))
            nginx[26] += 1;
        if ((mas[i].find("client_max_body_size ") != -1) && (mas[i].find("#") == -1))
            nginx[27] = 1;
        if ((mas[i].find("large_client_header_buffers ") != -1) && (mas[i].find("#") == -1))
            nginx[28] = 1;
        if ((mas[i].find("limit_conn_zone ") != -1) && (mas[i].find("#") == -1))
            nginx[29] += 1;
        if ((mas[i].find("server") != -1) && (mas[i].find("#") == -1)) {
            int j = i;
            do {
                if ((mas[j].find("limit_conn limitperip") != -1) && (mas[j].find("#") == -1))
                    nginx[29] += 1;
                j++;
            } while (mas[j].find("}") == -1);
        }
        if ((mas[i].find("limit_req_zone ") != -1) && (mas[i].find("#") == -1))
            nginx[30] += 1;
        if ((mas[i].find("location /") != -1) && (mas[i].find("#") == -1)) {
            int j = i;
            do {
                if ((mas[j].find("limit_req ") != -1) && (mas[i].find("#") == -1))
                    nginx[30] += 1;
                j++;
            } while (mas[j].find("}") == -1);
        }
        if ((mas[i].find("add_header X-Frame-Options \"SAMEORIGIN\"") != -1) && (mas[i].find("#") == -1))
            nginx[31] = 1;
        if ((mas[i].find("add_header X-Content-Type-Options \"nosniff\"") != -1) && (mas[i].find("#") == -1))
            nginx[32] = 1;
        if ((mas[i].find("add_header X-Xss-Protection \"1; mode=block\"") != -1) && (mas[i].find("#") == -1))
            nginx[33] = 1;
        if ((mas[i].find("add_header Content-Security-Policy \"default-src \'self\'\"") != -1) &&
            (mas[i].find("#") == -1))
            nginx[34] = 1;
        if ((mas[i].find("add_header Referrer-Policy \"no-referrer\"") != -1) && (mas[i].find("#") == -1))
            nginx[35] = 1;
        if ((mas[i].find("ssl_ciphers ") != -1) && (mas[i].find("proxy") == -1) && (mas[i].find("#") == -1))
            nginx[14] += 1;
        if ((mas[i].find("proxy_ssl_ciphers ") != -1) && (mas[i].find("#") == -1))
            nginx[14] += 1;
        if ((mas[i].find("include ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, strlen("include ") + 1);
            s.erase(s.size() - 1);
            if (s.find("/*.conf") != -1) {
                string a = s;
                a.erase(a.rfind("/"));
                for (const auto &entry : fs::directory_iterator(a))
                    nginx_func(entry.path().string().c_str());
            } else {
                nginx_func(s.c_str());
            }
        }
    }
}

void apache_func(const char *file) {
    int os;
    switch (os = check(file)) {
        case 1:
            return;
        case 2:
            return;
    }
    ifstream f;
    f.open(file, ios_base::in | ios_base::binary);
    string s;
    int k = 0;
    while (!f.eof()) {
        getline(f, s);
        k++;
    }
    f.clear();
    f.seekg(0, ios_base::beg);
    string *mas = new string[k];
    int i = 0;
    while (!f.eof()) {
        getline(f, s);
        mas[i] = s;
        i++;
    }
    f.close();
    for (i = 0; i < k; i++) {
        if ((mas[i].find("log_config_module") != -1) && (mas[i].find("#") == -1))
            apache[0] = 1;
        if ((mas[i].find("dav") != -1) && (mas[i].find("#") == -1))
            apache[1] = -1;
        if ((mas[i].find("states_module") != -1) && (mas[i].find("#") == -1))
            apache[2] = -1;
        if ((mas[i].find("autoindex_module") != -1) && (mas[i].find("#") == -1))
            apache[3] = -1;
        if ((mas[i].find("proxy") != -1) && (mas[i].find("#") == -1))
            apache[4] = -1;
        if ((mas[i].find("userdir_module") != -1) && (mas[i].find("#") == -1))
            apache[5] = -1;
        if ((mas[i].find("info_module") != -1) && (mas[i].find("#") == -1))
            apache[6] = -1;
        if ((mas[i].find("mod_auth_basic") != -1) && (mas[i].find("#") == -1))
            apache[7] = -1;
        if ((mas[i].find("mod_auth_digest") != -1) && (mas[i].find("#") == -1))
            apache[7] = -1;
        if (((mas[i].find("User www-data") != -1) && (os == 4)) || ((mas[i].find("User apache") != -1) && (os == 3)) ||
            (mas[i].find("User ${APACHE_RUN_USER}") != -1))
            apache[8] += 1;
        if (((mas[i].find("Group www-data") != -1) && (os == 4)) ||
            ((mas[i].find("Group apache") != -1) && (os == 3)) || (mas[i].find("Group ${APACHE_RUN_GROUP}") != -1))
            apache[8] += 1;
        if ((mas[i].find("<Directory />") != -1) && (mas[i].find("#") == -1)) {
            apache[17] = 0;
            int j = i;
            do {
                if ((mas[j].find("Require all denied") != -1) && (mas[j].find("#") == -1))
                    apache[9] = 1;
                if ((mas[j].find("AllowOverride None") != -1) && (mas[j].find("#") == -1))
                    apache[11] = 1;
                if ((mas[j].find("AllowOverrideList ") != -1) && (mas[j].find("#") == -1))
                    cout << "Bad, AllowOverrideList" << endl;
                if ((mas[j].find("Options ") != -1) && (mas[j].find("#") == -1))
                    if (mas[j].find("None") != -1)
                        apache[13] = 1;
                if ((mas[j].find("<LimitExceot GET POST OPTIONS>") != -1) && (mas[j].find("#") == -1)) {
                    do {
                        if ((mas[j].find("Require all denied") != -1) && (mas[j].find("#") == -1))
                            apache[17] = 1;
                        j++;
                    } while (mas[j].find("</LimitExcept>") == -1);
                }
                j++;
            } while (mas[j].find("</Directory>") == -1);
        }
        if ((mas[i].find("<Directory ") != -1) && (mas[i].find("<Directory />") == -1) && (mas[i].find("#") == -1)) {
            int j = i;
            apache[10] = apache[12] = apache[17] = 0;
            do {
                if ((mas[j].find("Require ") != -1) && (mas[j].find("#") == -1))
                    apache[10] = 1;
                if ((mas[j].find("AllowOverride") != -1) && (mas[j].find("#") == -1))
                    if (mas[j].find(" None") != -1)
                        apache[12] = 1;
                    else
                        cout << "Bad, AllowOverride" << endl;
                if ((mas[j].find("Options ") != -1) && (mas[j].find("#") == -1))
                    if (mas[j].find("Includes") != -1)
                        apache[15] = -1;
                if ((mas[j].find("<LimitExceot GET POST OPTIONS>") != -1) && (mas[j].find("#") == -1)) {
                    do {
                        if ((mas[j].find("Require all denied") != -1) && (mas[j].find("#") == -1))
                            apache[17] = 1;
                        j++;
                    } while (mas[j].find("</LimitExcept>") == -1);
                }
                j++;
            } while (mas[j].find("</Directory>") == -1);
        }
        if ((mas[i].find("<Directory /var/www") != -1) && (mas[i].find("#") == -1)) {
            int j = i;
            do {
                if ((mas[j].find("Options ") != -1) && (mas[j].find("#") == -1))
                    if ((mas[j].find("None") != -1) || (mas[j].find("Multiviews") != -1))
                        apache[14] = 1;
                j++;
            } while (mas[j].find("</Directory>") == -1);
        }
        if ((mas[i].find("<Location ") != -1) && (mas[i].find("#") == -1)) {
            int j = i;
            apache[10] = 0;
            do {
                if (mas[j].find("Require ") != -1)
                    apache[10] = 1;
                j++;
            } while (mas[j].find("</Location>") == -1);
        }
        if ((mas[i].find("example.conf") != -1) && (mas[i].find("#") != -1))
            apache[16] = -1;
        if ((mas[i].find("<IfModule proxy_html_module>") != -1) && (mas[i].find("#") == -1))
            apache[16] += 1;
        if ((mas[i].find("TraceEnable off") != -1) && (mas[i].find("#") == -1))
            apache[18] = 1;
        if ((mas[i].find("RewriteEngine ") != -1) && (mas[i].find("#") == -1))
            if (mas[i].find("On") != -1)
                apache[19] += 1;
        if ((mas[i].find("RewriteCond ") != -1) && (mas[i].find("#") == -1))
            if (mas[i].find("!HTTP/1\\.1$") != -1)
                apache[19] += 1;
        if ((mas[i].find("RewriteRule ") != -1) && (mas[i].find("#") == -1))
            apache[19] += 1;
        if (mas[i].find("<FilesMatch \"^\\.ht\">") != -1) {
            int j = i;
            do {
                if (mas[j].find("Require all denied") != -1)
                    apache[20] = 1;
                j++;
            } while (mas[j].find("</FilesMatch>") == -1);
        }
        if ((mas[i].find("<FilesMatch \"^.*$\">") != -1) && (mas[i].find("#") == -1)) {
            int j = i;
            do {
                if (mas[j].find("Require all denied") != -1)
                    apache[21] += 1;
                j++;
            } while (mas[j].find("</FilesMatch>") == -1);
        }
        if ((mas[i].find("<FilesMatch \"^.*\\.(css|html?|js|pdf|txt|xml|xsl|gif|ico|jpe?g|png)$\">") != -1) &&
            (mas[i].find("#") == -1)) {
            int j = i;
            do {
                if (mas[j].find("Require all denied") != -1)
                    apache[21] += 1;
                j++;
            } while (mas[j].find("</FilesMatch>") == -1);
        }
        if ((mas[i].find("RewriteCond %{HTTP_HOST}") != -1) && (mas[i].find("#") == -1))
            apache[22] += 1;
        if ((mas[i].find("RewriteCond %{REQUEST_URI}") != -1) && (mas[i].find("#") == -1))
            apache[22] += 1;
        if ((mas[i].find("Listen ") != -1) && (mas[i].find("#") == -1))
            apache[23] = 1;
        if ((mas[i].find("Header always append X-Frame-Options ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("SAMEORIGIN") != -1) || (mas[i].find("DENY") != -1))
                apache[24] = 1;
        if ((mas[i].find("LogLevel ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("notice core:info") != -1))
                apache[25] += 1;
        if ((mas[i].find("ErrorLog ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("syslog") != -1))
                apache[26] = 1;
            else
                apache[24] += 1;
        if ((mas[i].find("LogFormat ") != -1) && (mas[i].find("#") == -1))
            apache[27] += 1;
        if ((mas[i].find("CustomLog ") != -1) && (mas[i].find("#") == -1))
            if (((mas[i].find("log/access_log combined") != -1) && (os == 3)) ||
                ((mas[i].find("/var/log/apache2/vhost.log vhost_combined ") != -1) && (os == 4)))
                apache[27] += 1;
        if ((mas[i].find("security2_module") != -1) && (mas[i].find("#") == -1))
            apache[28] = 1;
        if ((mas[i].find("SSLCertificateFile ") != -1) && (mas[i].find("#") == -1))
            apache[29] += 1;
        if ((mas[i].find("SSLCertificateKeyFile ") != -1) && (mas[i].find("#") == -1))
            apache[29] += 1;
        if ((mas[i].find("SSLCertificateChainFile ") != -1) && (mas[i].find("#") == -1))
            apache[29] += 1;
        if ((mas[i].find("SSLProtocol ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("TLSv1.2") != -1))
                apache[30] = 1;
        if ((mas[i].find("SSLHonorCipherOrder On") != -1) && (mas[i].find("#") == -1))
            apache[31] += 1;
        if ((mas[i].find("SSLCipherSuite ") != -1) && (mas[i].find("#") == -1))
            apache[31] += 1;
        if ((mas[i].find("<VirtualHost ") != -1) && (mas[i].find("#") == -1)) {
            int j = i;
            apache[34] = 0;
            do {
                if ((mas[j].find("SSLHonorCipherOrder On") != -1) && (mas[j].find("#") == -1))
                    apache[34] += 1;
                if ((mas[j].find("SSLCipherSuite ") != -1) && (mas[j].find("#") == -1))
                    apache[34] += 1;
                j++;
            } while (mas[j].find("</VirtualHost>") == -1);
        }
        if ((mas[i].find("SSLInsecureRenegotiation off") != -1) && (mas[i].find("#") == -1))
            apache[32] = 1;
        if ((mas[i].find("SSLCompression off") != -1) && (mas[i].find("#") == -1))
            apache[33] = 1;
        if ((mas[i].find("Redirect ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("permanent / https:") != -1))
                apache[35] = 1;
        if ((mas[i].find("SSLUseStapling On") != -1) && (mas[i].find("#") == -1))
            apache[36] += 1;
        if ((mas[i].find("SSLStaplingCache ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("shmcb:logs/ssl_staple_cache(512000)") != -1) ||
                (mas[i].find("dbm:logs/ssl_staple_cache.db") != -1) ||
                (mas[i].find("dc:UNIX:logs/ssl_staple_socket") != -1))
                apache[36] += 1;
        if ((mas[i].find("Header always set Strict-Transport-Security ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("\"max-age=600\"") != -1) ||
                (mas[i].find("\"max-age=600\"; includeSubDomains; preload") != -1))
                apache[37] = 1;
        if ((mas[i].find("SSLCipherSuite ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("EECDH:EDH:!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA") != -1))
                apache[38] = 1;
        if ((mas[i].find("ServerTokens ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("Prod") != -1) || (mas[i].find("ProductOnly") != -1))
                apache[39] = 1;
        if ((mas[i].find("ServerSignature Off") != -1) && (mas[i].find("#") == -1))
            apache[40] = 1;
        if ((mas[i].find("FileETag ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("None") != -1) || (mas[i].find("MTime Size") != -1))
                apache[41] = 1;
        if ((mas[i].find("KeepAlive On") != -1) && (mas[i].find("#") == -1))
            apache[43] = 1;
        if ((mas[i].find("Header edit Set-Cookie ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("^(.*)$ $1;HttpOnly;Secure") != -1))
                apache[53] = 1;
        if ((mas[i].find("Header set X-XSS-Protection ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("1; mode=block") != -1))
                apache[54] = 1;
        if ((mas[i].find("SecAuditLog ") != -1) && (mas[i].find("#") == -1))
            apache[55] = 1;
        if ((mas[i].find("SecRuleEngine On") != -1) && (mas[i].find("#") == -1))
            apache[56] = 1;
        if ((mas[i].find("SecServerSignature ") != -1) && (mas[i].find("#") == -1))
            apache[57] = 1;
        if ((mas[i].find("Deny ") != -1) && (mas[i].find("#") == -1))
            if ((mas[i].find("from all") != -1))
                apache[58] = 1;
        if ((mas[i].find("Timeout ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, sizeof("Timeout"));
            if ((atoi(s.c_str()) <= 10) && (atoi(s.c_str()) > 0))
                apache[42] = 1;
        }
        if ((mas[i].find("MaxKeepAliveRequests ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, sizeof("MaxKeepAliveRequests"));
            if (atoi(s.c_str()) >= 100)
                apache[44] = 1;
        }
        if ((mas[i].find("KeepAliveTimeout ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, sizeof("KeepAliveTimeout"));
            if ((atoi(s.c_str()) <= 15) && (atoi(s.c_str()) > 0))
                apache[45] = 1;
        }
        if ((mas[i].find("LimitRequestline ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, sizeof("LimitRequestline"));
            if ((atoi(s.c_str()) <= 512) && (atoi(s.c_str()) > 0))
                apache[48] = 1;
        }
        if ((mas[i].find("LimitRequestFields ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, sizeof("LimitRequestFields"));
            if ((atoi(s.c_str()) <= 100) && (atoi(s.c_str()) > 0))
                apache[49] = 1;
        }
        if ((mas[i].find("LimitRequestFieldsize ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, sizeof("LimitRequestFieldsize"));
            if ((atoi(s.c_str()) <= 1024) && (atoi(s.c_str()) > 0))
                apache[50] = 1;
        }
        if ((mas[i].find("LimitRequestBody ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, sizeof("LimitRequestBody"));
            if ((atoi(s.c_str()) <= 102400) && (atoi(s.c_str()) > 0))
                apache[51] = 1;
        }
        if ((mas[i].find("LimitXMLRequestBody ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, sizeof("LimitXMLRequestBody"));
            if ((atoi(s.c_str()) <= 1048576) && (atoi(s.c_str()) > 0))
                apache[52] = 1;
        }
        if ((mas[i].find("RequestReadTimeout ") != -1) && (mas[i].find("header") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s = s.substr(s.find("header"), s.find(",Min") - s.find("header"));
            s.erase(0, sizeof("header"));
            if (s.find("-") != -1)
                s.erase(0, s.find("-") + 1);
            if ((atoi(s.c_str()) <= 40) && (atoi(s.c_str()) > 0))
                apache[46] = 1;
        }
        if ((mas[i].find("RequestReadTimeout ") != -1) && (mas[i].find("body") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s = s.substr(s.find("body"), s.find(",Min") - s.find("body"));
            s.erase(0, sizeof("body"));
            if ((atoi(s.c_str()) <= 20) && (atoi(s.c_str()) > 0))
                apache[47] = 1;
        }
        if ((mas[i].find("Include ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, strlen("Include "));
            string a;
            a = file;
            a.erase(a.rfind("/"), a.size() - a.rfind("/"));
            a = a + "/" + s;
            s = a;
            if ((s.find("/*.conf") != -1) || (s.find("/*.load") != -1)) {
                a = s;
                a.erase(a.rfind("/"));
                for (const auto &entry : fs::directory_iterator(a))
                    apache_func(entry.path().string().c_str());
            } else {
                apache_func(s.c_str());
            }
        }
        if ((mas[i].find("IncludeOptional ") != -1) && (mas[i].find("#") == -1)) {
            s = mas[i];
            s.erase(0, strlen("IncludeOptional "));
            string a;
            a = file;
            a.erase(a.rfind("/"), a.size() - a.rfind("/"));
            a = a + "/" + s;
            s = a;
            if ((s.find("/*.conf") != -1) || (s.find("/*.load") != -1)) {
                a = s;
                a.erase(a.rfind("/"));
                for (const auto &entry : fs::directory_iterator(a))
                    apache_func(entry.path().string().c_str());
            } else {
                apache_func(s.c_str());
            }
        }
    }
    f.close();
    delete[] mas;
}

int main(int argc, char *argv[]) {
    const char *file;
    if (argc == 3) {
        file = argv[2];
        if (check(file) == 1) {
            cout << "Your file: " << file << " is not a configuration one, please try something else" << endl;
            return -1;
        }
        if (check(file) == 2) {
            cout << "Error, cnat open file: " << file << " , please try something else" << endl;
            return -1;
        }
        mass_update();
        if (strcmp(argv[1], "apache") == 0) {
            apache_func(file);
            apache_conclude();
        } else if (strcmp(argv[1], "nginx") == 0) {
            nginx_func(file);
            nginx_conclude();
        } else if (strcmp(argv[1], "docker") == 0) {
            docker_func(file);
            docker_conclude();
        } else if ((strcmp(argv[1], "kubernetes") == 0) || (strcmp(argv[1], "kube") == 0)) {
            kube_conclude(kube_func(file));
        } else {
            cout << "Invalid parameters, try ./chcinfig --help to see valid parateters" << endl;
        }
    } else if (argc == 2) {
        if (strcmp(argv[1], "--help") == 0) {
            cout << "chconfig:" << endl << "./chconfig [name_of_program] [path_to_file]" << endl
                 << "For example: ./chconfig apache /etc/httpd/httpd.conf" << endl;
            cout << "List of programs:" << endl << "	apache (files httpd.conf and apache2.conf)" << endl
                 << "	nginx (file nginx.conf)" << endl;
            cout << "	docker (file daemon.json)" << endl
                 << "	kubernetes or kube (files kube-apiserver.yaml,kube-controller-manager.yaml,kube-scheduler.yaml and 10-kubeadm.conf"
                 << endl;
        } else {
            cout << "Invalid parameters, try ./chcinfig --help to see valid parateters" << endl;
        }
    } else {
        cout << "Invalid parameters, try ./chcinfig --help to see valid parateters" << endl;
    }
    return 0;
}
