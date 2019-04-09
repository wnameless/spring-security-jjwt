/*
 *
 * Copyright 2019 Wei-Ming Wu
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */
package com.github.wnameless.spring.security.jjwt;

import java.util.Date;
import java.util.concurrent.ConcurrentMap;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.Serializer;

public class MemoryDBJwtExpirationExtendingService
    implements JwtExpirationExtendingService {

  private DB db = DBMaker.memoryDB().make();
  private ConcurrentMap<String, Date> map =
      db.hashMap("map", Serializer.STRING, Serializer.DATE).create();

  @Override
  public Date getTokenLastLoginTime(String token) {
    return map.get(token);
  }

  @Override
  public void setTokenLastLoginTime(String token) {
    map.put(token, new Date());
  }

  @Override
  public Date deleteTokenLastLoginTime(String token) {
    return map.remove(token);
  }

}
