rockspec_format = '3.0'
package = 'lua-resty-jwt'
version = 'dev-0'
source = {
  url = 'file://.'
}
description = {
  summary = 'JWT for ngx_lua and LuaJIT.',
  detailed = [[
    This library requires an nginx build
    with OpenSSL, the ngx_lua module,
    the LuaJIT 2.0, the lua-resty-hmac,
    and the lua-resty-string,
  ]],
  homepage = 'https://github.com/cdbattags/lua-resty-jwt',
  license = 'Apache License Version 2'
}
dependencies = {
  'lua >= 5.1',
  'lua-resty-openssl >= 0.6.8'
}
build = {
  type = 'builtin',
  modules = {
    ['resty.jwt'] = 'lib/resty/jwt.lua',
    ['resty.evp'] = 'lib/resty/evp.lua',
    ['resty.jwt-validators'] = 'lib/resty/jwt-validators.lua',
    ['resty.hmac'] = 'third-party/lua-resty-hmac/lib/resty/hmac.lua'
  }
}