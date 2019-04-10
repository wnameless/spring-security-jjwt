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
import java.util.Optional;
import java.util.function.BiFunction;

import io.jsonwebtoken.Claims;

/**
 * 
 * {@link JwtExpirationExtendingPolicy} is used to describe the logic whether to
 * extend an expired JWT or not.
 *
 */
@FunctionalInterface
public interface JwtExpirationExtendingPolicy
    extends BiFunction<Claims, Optional<Date>, Boolean> {

  /**
   * Returns true if the given expired JWT {@link Claims} can be extended, false
   * otherwise.
   * 
   * @param jwtClaims
   *          a expired JWT {@link Claims}
   * @param lastLoginTime
   *          the last login time of given JWT
   * @return true if the given expired JWT {@link Claims} can be extended, false
   *         otherwise
   */
  @Override
  Boolean apply(Claims jwtClaims, Optional<Date> lastLoginTime);

}
