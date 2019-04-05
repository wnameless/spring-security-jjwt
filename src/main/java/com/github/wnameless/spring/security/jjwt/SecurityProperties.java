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

/**
 * 
 * {@link SecurityProperties} defines necessary methods to set up the JWT
 * security service.
 *
 */
interface SecurityProperties {

  /**
   * Returns the endpoint of the JWT authentication.
   * 
   * @return a string url
   */
  String getJwtAuthUrl();

  /**
   * Returns the JWT signing key.
   * 
   * @return a string at least 512 bytes long
   */
  String getJwtSecret();

  /**
   * Returns the JWT expiration time in milliseconds.
   * 
   * @return a long represents milliseconds
   */
  long getJwtExpiration();

}
