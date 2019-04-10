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

/**
 * 
 * {@link MapDBJwtExpirationExtendingService} is an implementation of
 * {@link JwtExpirationExtendingService} based on the MapDB library.
 *
 */
public class MapDBJwtExpirationExtendingService
    implements JwtExpirationExtendingService {

  private final DB db;
  private final ConcurrentMap<String, Date> jwtLastLogin;

  /**
   * Creates a {@link MapDBJwtExpirationExtendingService} with in-memory DB and
   * a 14-days data expiration after any record has been updated or created.
   */
  public MapDBJwtExpirationExtendingService() {
    db = DBMaker.memoryDB().make();
    jwtLastLogin =
        db.hashMap("jwtLastLogin", Serializer.STRING, Serializer.DATE)
            .expireAfterCreate(14, TimeUnit.DAYS)
            .expireAfterUpdate(14, TimeUnit.DAYS).create();
  }

  /**
   * Creates a {@link MapDBJwtExpirationExtendingService} by given MapDB
   * {@link DB} and a data expiration time in milliseconds.
   * 
   * @param db
   *          a MapDB {@link DB}
   * @param expireInMillis
   *          the expiration time in milliseconds after any record has been
   *          updated or created
   */
  public MapDBJwtExpirationExtendingService(DB db, long expireInMillis) {
    this.db = Objects.requireNonNull(db);
    jwtLastLogin =
        this.db.hashMap("jwtLastLogin", Serializer.STRING, Serializer.DATE)
            .expireAfterCreate(expireInMillis, TimeUnit.MILLISECONDS)
            .expireAfterUpdate(expireInMillis, TimeUnit.MILLISECONDS).create();
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
