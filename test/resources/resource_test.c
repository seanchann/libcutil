/*
 *
 * seanchann <xqzhou@bj-jyd.cn>
 *
 * See docs/ for more information about
 * the  project.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

#include "resource_test.h"

void rest_test_list(struct ast_variable *headers,
                    struct rest_test_list_var_args *args,
                    struct ast_ari_response *response) {
  RAII_VAR(struct ast_json *, json, NULL, ast_json_unref);

  json = ast_json_pack("{s: s, s: s}", "test", "hello world", "code", "200ok");

  if (!json) {
    ast_ari_response_alloc_failed(response);
    return;
  }

  ast_ari_response_ok(response, ast_json_ref(json));
}
