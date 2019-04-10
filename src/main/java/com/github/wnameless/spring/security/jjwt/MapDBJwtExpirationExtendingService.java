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

  public enum ExpireAfter {
    CREATE, UPDATE, GET;
  }

  private final DB db;
  private final ConcurrentMap<String, Date> jwtLastLogin;

  public MapDBJwtExpirationExtendingService() {
    db = DBMaker.memoryDB().make();
    jwtLastLogin =
        db.hashMap("jwtLastLogin", Serializer.STRING, Serializer.DATE)
            .expireAfterUpdate(14, TimeUnit.DAYS).create();
  }

  public MapDBJwtExpirationExtendingService(DB db, ExpireAfter expireAfter,
      long milliseconds) {
    this.db = Objects.requireNonNull(db);

    Objects.requireNonNull(expireAfter);
    switch (expireAfter) {
      case CREATE:
        jwtLastLogin = db
            .hashMap("jwtLastLogin", Serializer.STRING, Serializer.DATE)
            .expireAfterCreate(milliseconds, TimeUnit.MILLISECONDS).create();
        break;
      case UPDATE:
        jwtLastLogin = db
            .hashMap("jwtLastLogin", Serializer.STRING, Serializer.DATE)
            .expireAfterUpdate(milliseconds, TimeUnit.MILLISECONDS).create();
        break;
      case GET:
        jwtLastLogin =
            db.hashMap("jwtLastLogin", Serializer.STRING, Serializer.DATE)
                .expireAfterGet(milliseconds, TimeUnit.MILLISECONDS).create();
        break;
      default:
        jwtLastLogin = db
            .hashMap("jwtLastLogin", Serializer.STRING, Serializer.DATE)
            .expireAfterUpdate(milliseconds, TimeUnit.MILLISECONDS).create();
    }
  }

  @Override
  public Date getTokenLastLoginTime(String token) {
    return jwtLastLogin.get(token);
  }

  @Override
  public void setTokenLastLoginTime(String token) {
    jwtLastLogin.put(token, new Date());
  }

}
