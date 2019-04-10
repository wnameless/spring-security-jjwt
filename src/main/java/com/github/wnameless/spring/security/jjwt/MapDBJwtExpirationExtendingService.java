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
import java.util.Objects;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.Serializer;

public class MapDBJwtExpirationExtendingService
    implements JwtExpirationExtendingService {

  private final DB db;
  private final ConcurrentMap<String, Date> map;

  public MapDBJwtExpirationExtendingService() {
    db = DBMaker.memoryDB().make();
    map = db.hashMap("map", Serializer.STRING, Serializer.DATE)
        .expireAfterUpdate(14, TimeUnit.DAYS).create();
  }

  public MapDBJwtExpirationExtendingService(DB db, long expiration) {
    this.db = Objects.requireNonNull(db);
    map = db.hashMap("map", Serializer.STRING, Serializer.DATE)
        .expireAfterUpdate(expiration, TimeUnit.MILLISECONDS).create();
  }

  @Override
  public Date getTokenLastLoginTime(String token) {
    return map.get(token);
  }

  @Override
  public void setTokenLastLoginTime(String token) {
    map.put(token, new Date());
  }

}
