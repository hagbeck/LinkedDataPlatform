/*
    The MIT License (MIT)

    Copyright (c) 2015, Hans-Georg Becker, http://orcid.org/0000-0003-0432-294X

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
 */

package de.tu_dortmund.ub.data.ldp.storage;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Properties;

/**
 * Linked Data Storage Interface
 *
 * @author Dipl.-Math. Hans-Georg Becker, M.L.I.S. (UB Dortmund)
 * @version 2015-08-15
 *
 */
public interface LinkedDataStorage {

    void init(Properties config) throws LinkedDataStorageException;

    HashMap<String,String> health(Properties properties);


    String getResource(String resource, String format) throws LinkedDataStorageException;

    String getResource(String resource, String format, boolean isAuthorized) throws LinkedDataStorageException;

    String getResource(String graph, String resource, String format) throws LinkedDataStorageException;

    String getResource(String graph, String resource, String format, boolean isAuthorized) throws LinkedDataStorageException;


    String getAccessRights(String resource) throws LinkedDataStorageException;

    String getAccessRights(String graph, String resource) throws LinkedDataStorageException;


    String searchResource(Properties query, String format) throws LinkedDataStorageException;

    String searchResource(Properties query, String format, boolean isAuthorized) throws LinkedDataStorageException;

    String searchResource(String graph, Properties query, String format) throws LinkedDataStorageException;

    String searchResource(String graph, Properties query, String format, boolean isAuthorized) throws LinkedDataStorageException;


    String sparqlQuery(String query, String format) throws LinkedDataStorageException;

    String sparqlQuery(String query, String format, boolean isAuthorized) throws LinkedDataStorageException;

    String sparqlQuery(String graph, String query, String format) throws LinkedDataStorageException;

    String sparqlQuery(String graph, String query, String format, boolean isAuthorized) throws LinkedDataStorageException;


    String sparqlUpdate(String data) throws LinkedDataStorageException;

}
