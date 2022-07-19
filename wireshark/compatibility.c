#include <ctype.h>
#include <stdlib.h>

#include <lua.h>
#include <lauxlib.h>
#include "libdecrypt.h"

// Convert key of the form [num num num num] to the corresponding binary string
static int convert_key(lua_State *L) {
  size_t encoded_len;
  const char* encoded = lua_tolstring(L, 1, &encoded_len);

  // TODO void*
  struct parseKey_return converted = parseKey((void *)encoded, encoded_len);
  if (converted.r0 == NULL) {
    return 0;
  }
  
  lua_pushlstring(L, converted.r0, converted.r1);
  freeKey(converted.r0);

  return 1;
}

static int read_packet(lua_State *L) {
  size_t pkt_len;
  const char *pkt = lua_tolstring(L, 1, &pkt_len);
  size_t key_len;
  const char *key = lua_tolstring(L, 2, &key_len);
  // TODO: use actual error handling mechanisms?
  if (pkt == NULL || key == NULL) {
    lua_pushliteral(L, "");
    lua_pushnumber(L, 255);
    return 2;
  }

  GoInt plaintext_len = PlaintextLen(pkt_len);
  if (plaintext_len <= 0) {
    lua_pushliteral(L, "");
    lua_pushnumber(L, 254);
    return 2;
  }

  char* plaintext = malloc(plaintext_len);

  struct readPacket_return res = readPacket(
      plaintext, plaintext_len,
      // TODO: we know that these void pointers don't get modified, but...
      (void*)pkt, pkt_len,
      (void*)key, key_len
  );

  // TODO: use actual lua error handling mechanisms?
  lua_pushlstring(L, plaintext, res.r0);
  lua_pushnumber(L, res.r1);
  free(plaintext);

  return 2;
}

// https://stackoverflow.com/questions/55508395/lua-c-lib-windows-the-specified-procedure-could-not-be-found 
#ifdef DLLEXPORT
__declspec(dllexport) int luaopen_libcompat(lua_State* L) {
#else
int luaopen_libcompat(lua_State* L) {
#endif
  lua_register(L, "read_packet", read_packet);
  lua_register(L, "convert_key", convert_key);
  return 1;
}
