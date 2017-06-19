# restful 用户接口说明

基于libcutil的restful接口，用户可以方便的设计自己的`RESTFUL API`。构建一个自定义的restful服务
包括如下几个方面：

- 配置HTTP server以及restful server
- 编写restful 处理函数，并且注册它

## 配置HTTP server

http server是libcutil内置的mini server。其配置数据结构如下：

```c
struct http_server_config {
  unsigned char enabled : 1;
  char          bindaddr[64];
  char          bindport[32];

  char prefix[32];
  char server_name[128];
  char redirect[128];
  char sessionlimit[16];
  char session_inactivity[16];
  char session_keep_alive[16];

  unsigned char tlsenable : 1;
  char          tlsbindaddr[64];
  char          tlscertfile[64];
  char          tlsprivatekey[64];
}
```

- enabled: 是否使能http服务
- bindaddr: 用于绑定http服务的地址，此地址不能为空
- bindport: 用于提供http服务的端口，默认值是8088
- prefix: 指定一个url的前缀，这个设定会影响所有的请求连接
- server_name:  服务器的名称，在http的应答的`Server`头字段中会填写此值，默认值是`cutil/{version}`
- redirect: 重定向URI，这个部分可以设定一个默认的页面，语法为 `<from> <to>`
- sessionlimit: 在任意时刻，所能允许的最大的http会话。默认指是`100`
- session_inactivity: 配置一个以毫秒为单位的时间，当http连接关闭之前以等待更多的数据
- session_keep_alive: 指定在持续连接上等待下一个http请求的时间，单位是毫秒
- tlsenable: 是否使能HTTPS
- tlsbindaddr: 用于绑定https服务的地址以及端口，此地址和端口不能为空
- tlscertfile: 证书文件的全路径地址。只支持.pem格式
- tlsprivatekey: 私钥文件的的全路径地址。只支持.pem格式，如果没有指定，那么会根据`tlscertfile`所配置的地址，来进行检索

初始化实例代码：

```c
struct http_server_config   config;

config.enabled = 1;
snprintf(config.bindaddr,
         sizeof(config.bindaddr), "0.0.0.0");
snprintf(config.bindport,
         sizeof(config.bindport), "19080");
snprintf(config.prefix,      sizeof(config.prefix),      "cutiltest");
snprintf(config.server_name, sizeof(config.server_name), "restful test server");

config.tlsenable = 0;

ast_http_init(&config);
```

## 配置restful

restful的配置数据结构分为两段，一部分为服务配置，一部分为用户配置

```
struct ast_ari_conf_general {
  /*! Enabled by default, disabled if false. */
  int enabled;

  /*! Write timeout for websocket connections */
  int write_timeout;

  /*! Encoding format used during output (default compact). */
  enum ast_json_encoding_format format;

  /*! Authentication realm */
  char auth_realm[ARI_AUTH_REALM_LEN];

  AST_DECLARE_STRING_FIELDS(
    AST_STRING_FIELD(allowed_origins);
    );
}
```

- enabled: 是否使能restful服务框架
- write_timeout: 针对websocket连接的写超时
- format: restful的应答的json的格式，分为`完全可读的模式`以及`压紧模式`
- auth: 鉴权的域名，可默认为空
- allowed_origins: 允许跨域访问的地址。如果有多个，用`,`分割。`*`表示允许所有的源

用户部分用来对发起的请求进行鉴权，目前内部只支持basic的方式

```
struct ast_ari_conf_user {

  char *username;

  char password[ARI_PASSWORD_LEN];

  enum ast_ari_password_format password_format;


  int read_only;

  char resources[512];
}
```

- username: 鉴权的用户名
- password: 用户密码
- password_format: 密码的格式。 目前有两种，一种是明文的格式，一种是密文的格式(密文可以通过`restful mkpassword 123456`来生成)
- read_only: 如果配置为真，那么用户只被授权发起只读的请求，此配置项基于resource配置来管理用户访问的资源。
- resources: 此用户可以访问那些资源，如果为空，那么没有限制，可以访问任何资源。如果有多个资源，请用`,`分割。

*初始化的例子可以参考test目录中的test_restful.c中的init_restful_mod()函数*

## 编写restful 处理逻辑

一般情况下我们新建三个文件，rest_*.c, resource_*.c, resource_*.h.

- `rest_*.c`用来注册实现restful回调的接口。
- `resource_*.*` 用来实现具体的业务逻辑。

rest_*.c 例子

```c
static void rest_test_list_cb(
  struct ast_tcptls_session_instance *ser,
  struct ast_variable                *get_params,
  struct ast_variable                *path_vars,
  struct ast_variable                *headers,
  struct ast_json                    *body,
  struct ast_ari_response            *response)
{
  struct rest_test_list_var_args args = {};

  rest_test_list(headers, &args, response);

fin: __attribute__((unused))
  return;
}

/*! \brief REST handler for /api-docs/channels.json */
static struct stasis_rest_handlers test = {
  .path_segment = "test",
  .callbacks    = {
    [AST_HTTP_GET] = rest_test_list_cb,
  },
  .num_children =      0,
  .children     = {}
};
```

如上所示，我们定义了一个路径为`test`的资源，此资源提供了get list的操作。它的子路径为空。
回调函数中的所有的`struct ast_variable`都可以以下面的方式进行遍历，并且获取

```c
for (i = path_vars; i; i = i->next) {
  if (strcmp(i->name, "configClass") == 0) {
    ...
  } else if (strcmp(i->name, "objectType") == 0) {
    ...
  } else if (strcmp(i->name, "id") == 0) {
    ...
  } else
  {}
}
```

`resource_*.*`主要负责具体的业务逻辑，并且构造应答。

```c
void rest_test_list(struct ast_variable            *headers,
                    struct rest_test_list_var_args *args,
                    struct ast_ari_response        *response)
{
  RAII_VAR(struct ast_json *, json, NULL, ast_json_unref);

  json = ast_json_pack(
    "{s: s, s: s}",
    "test",
    "hello world",
    "code",
    "200ok");

  if (!json) {
    ast_ari_response_alloc_failed(response);
    return;
  }

  ast_ari_response_ok(response, ast_json_ref(json));
}
```

如上面的例子所示，我们构造了json的串，并且返回了它。

### 注册处理handle

上文中，我们已经完成了处理函数的编写，下面挂载我们声明的`test`资源到restful的框架中去

```c
if (ast_ari_add_handler(&test)) {
  cutil_log(LOG_ERROR, "add restful  test resource error.\r\n");
}
```

上面注册的test就是我们前面声明的handle。至此，我们的一个`test`的restful接口就开发完成了。

*初始化的例子可以参考test目录中的test_restful.c以及resources目录*

*注意：整个程序中只允许一个http server实例以及一个restful实例运行，目前不支持多个实例*
