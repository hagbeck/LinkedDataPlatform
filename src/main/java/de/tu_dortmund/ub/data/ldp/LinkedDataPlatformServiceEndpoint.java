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
package de.tu_dortmund.ub.data.ldp;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.tu_dortmund.ub.data.ldp.auth.AuthorizationException;
import de.tu_dortmund.ub.data.ldp.auth.AuthorizationInterface;
import de.tu_dortmund.ub.data.ldp.auth.model.LoginResponse;
import de.tu_dortmund.ub.data.ldp.storage.LinkedDataStorage;
import de.tu_dortmund.ub.util.impl.Lookup;
import de.tu_dortmund.ub.util.rights.AnalyseIPRange;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.Properties;
import java.util.stream.Collectors;

/**
 * Linked Data Platform Service Endpoint
 *
 * @author Dipl.-Math. Hans-Georg Becker, M.L.I.S. (UB Dortmund)
 * @version 2015-08-08
 *
 */
public class LinkedDataPlatformServiceEndpoint extends HttpServlet {

    public static final  String     UTF_8                       = "UTF-8";
    private static       Properties config                      = new Properties();

    private static Logger logger = Logger.getLogger(LinkedDataPlatformServiceEndpoint.class.getName());

    public LinkedDataPlatformServiceEndpoint(String conffile) {

        // Init properties
        try {

            try (InputStream inputStream = new FileInputStream(conffile)) {

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, UTF_8))) {

                    this.config.load(reader);
                }
            }
        }
        catch (IOException e) {

            this.logger.error("something went wrong", e);
            this.logger.error(String.format("FATAL ERROR: Could not read '%s'!", conffile));
        }

        // init logger
        PropertyConfigurator.configure(this.config.getProperty(LDPStatics.SERVICE_LOG4J_CONF_IDENTIFIER));

        final String serviceName = this.config.getProperty(LDPStatics.SERVICE_NAME_IDENTIFIER);

        logger.info(String.format("[%s] Starting '" + LinkedDataPlatformServiceEndpoint.class.getName() + "' ...", serviceName));
        logger.info(String.format("[%s] conf-file = %s", serviceName, conffile));

        final String log4jConfFile = this.config.getProperty(LDPStatics.SERVICE_LOG4J_CONF_IDENTIFIER);

        logger.info(String.format("[%s] log4j-conf-file = %s", serviceName, log4jConfFile));
    }

    public void doOptions(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        response.setHeader("Access-Control-Allow-Methods", this.config.getProperty(LDPStatics.CORS_ACCESS_CONTROL_ALLOW_METHODS_IDENTIFIER));
        response.addHeader("Access-Control-Allow-Headers", this.config.getProperty(LDPStatics.CORS_ACCESS_CONTROL_ALLOW_HEADERS_IDENTIFIER));
        response.setHeader("Access-Control-Allow-Origin", this.config.getProperty(LDPStatics.CORS_ACCESS_CONTROL_ALLOW_ORIGIN_IDENTIFIER));
        response.setHeader("Accept", this.config.getProperty(LDPStatics.CORS_ACCEPT_IDENTIFIER));

        response.getWriter().println();
    }

    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        ObjectMapper mapper = new ObjectMapper();

        httpServletResponse.setHeader("Access-Control-Allow-Origin", this.config.getProperty(LDPStatics.CORS_ACCESS_CONTROL_ALLOW_ORIGIN_IDENTIFIER));

        // analyse ip range
        String ips = httpServletRequest.getHeader("X-Forwarded-For");

        boolean isTUintern = AnalyseIPRange.analyseAccessRights(ips, this.config.getProperty(LDPStatics.SERVICE_IPRANGE_TU_IDENTIFIER), config.getProperty(LDPStatics.SERVICE_IPRANGE_TU_EXCEPTIONS_IDENTIFIER));
        boolean isUBintern = AnalyseIPRange.analyseAccessRights(ips, this.config.getProperty(LDPStatics.SERVICE_IPRANGE_UB_IDENTIFIER), config.getProperty(LDPStatics.SERVICE_IPRANGE_UB_EXCEPTIONS_IDENTIFIER));

        this.logger.debug("[" + this.config.getProperty("service.name") + "] " + "Where is it from? " + httpServletRequest.getHeader("X-Forwarded-For") + ", " + isTUintern + ", " + isUBintern);

        String format = "html";
        String language = "de";
        String authorization = "";

        Enumeration<String> headerNames = httpServletRequest.getHeaderNames();
        while ( headerNames.hasMoreElements() ) {

            String headerNameKey = headerNames.nextElement();
            this.logger.debug("headerNameKey = " + headerNameKey + " / headerNameValue = " + httpServletRequest.getHeader(headerNameKey));

            if (headerNameKey.equals("Accept")) {

                if (httpServletRequest.getHeader(headerNameKey).contains("text/html")) {
                    format = "html";
                }
                else if (httpServletRequest.getHeader(headerNameKey).contains("application/rdf+xml")) {
                    format = "rdf.xml";
                }
                else if (httpServletRequest.getHeader(headerNameKey).contains("application/xhtml+xml")) {
                    format = "rdfa";
                }
                else if (httpServletRequest.getHeader(headerNameKey).contains("text/turtle")
                        || httpServletRequest.getHeader(headerNameKey).contains("application/x-turtle")
                        || httpServletRequest.getHeader(headerNameKey).contains("application/turtle")) {
                    format = "rdf.ttl";
                }
                else if (httpServletRequest.getHeader(headerNameKey).contains("application/ld+json")) {
                    format = "json";
                }
                else if (httpServletRequest.getHeader(headerNameKey).contains("application/json")) {
                    format = "json";
                }
                else if (httpServletRequest.getHeader(headerNameKey).contains("application/n-quads")) {
                    format = "nquads";
                }
            }
            if (headerNameKey.equals("Authorization")) {
                authorization = httpServletRequest.getHeader( headerNameKey );
            }
        }

        if (httpServletRequest.getParameter("format") != null) {
            format = httpServletRequest.getParameter("format");
        }

        this.logger.info("format = " + format);

        // language
        if (language != null && language.startsWith("de")) {
            language = "de";
        } else if (language != null && language.startsWith("en")) {
            language = "en";
        } else if (httpServletRequest.getParameter("lang") != null) {
            language = httpServletRequest.getParameter("lang");
        } else {
            language = this.config.getProperty(LDPStatics.SERVICE_LANGUAGE_DEFAULT_IDENTIFIER);
        }

        this.logger.info("language = " + language);

        String patronid = "";

        // if not exists token
        if (authorization.equals("")) {

            // if exists PaiaService-Cookie: read content
            Cookie[] cookies = httpServletRequest.getCookies();

            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals("PaiaService")) {

                        String value = URLDecoder.decode(cookie.getValue(), "UTF-8");
                        this.logger.info(value);
                        LoginResponse loginResponse = mapper.readValue(value, LoginResponse.class);

                        authorization = loginResponse.getAccess_token();
                        patronid = loginResponse.getPatron();

                        break;
                    }
                }
            }
        }

        this.logger.info("authorization: " + authorization);

        boolean isAuthorized = false;

        if (!authorization.equals("")) {

            if (Lookup.lookupAll(AuthorizationInterface.class).size() > 0) {

                AuthorizationInterface authorizationInterface = Lookup.lookup(AuthorizationInterface.class);
                // init Authorization Service
                authorizationInterface.init(this.config);

                try {

                    isAuthorized = authorizationInterface.isTokenValid(httpServletResponse, "data", patronid, authorization);
                }
                catch (AuthorizationException e) {

                    // TODO correct error handling
                    this.logger.error("[" + config.getProperty("service.name") + "] " + HttpServletResponse.SC_UNAUTHORIZED + "!");
                }
            } else {

                // TODO correct error handling
                this.logger.error("[" + this.config.getProperty("service.name") + "] " + HttpServletResponse.SC_INTERNAL_SERVER_ERROR + ": " + "Authorization Interface not implemented!");
            }
        }

        this.logger.debug("[" + config.getProperty("service.name") + "] " + "Authorization: " + authorization + " - " + isAuthorized);

        // ... - if not is authorized - against DFN-AAI service
        if (!isAuthorized) {

            // TODO if exists OpenAM-Session-Cookie: read content
            this.logger.debug("[" + config.getProperty("service.name") + "] " + "Authorization: " + authorization + " - " + isAuthorized);
        }

        // Linked Data Storage
        if (Lookup.lookupAll(LinkedDataStorage.class).size() > 0) {

            try {

                String graph = this.config.getProperty("storage.graph.default");

                // TODO get graph from request

                this.logger.debug("[" + config.getProperty("service.name") + "] " + "Graph: " + graph);

                // TODO is graph valid?
                if (!this.config.getProperty("storage.graphs").contains(graph)) {

                    httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad request - graph is not valid!");
                }
                else {

                    LinkedDataStorage linkedDataStorage = Lookup.lookup(LinkedDataStorage.class);
                    // init LinkedDataStorage
                    linkedDataStorage.init(this.config);

                    this.logger.debug("[" + config.getProperty("service.name") + "] " + "getPathInfo: " + httpServletRequest.getPathInfo());

                    if (httpServletRequest.getPathInfo().startsWith("/resource")) {

                        if (httpServletRequest.getParameter("uri") == null || httpServletRequest.getParameter("uri").equals("")) {

                            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad request. Parameter 'uri' not defined!");
                        } else {

                            String uri = URLDecoder.decode(httpServletRequest.getParameter("uri"), "UTF-8");

                            String resource = linkedDataStorage.getResource(graph, uri, format, isAuthorized);

                            if (resource == null) {

                                if (format.contains("html")) {

                                    httpServletResponse.setContentType("text/html;charset=UTF-8");
                                } else if (format.contains("rdf.xml")) {

                                    httpServletResponse.setContentType("application/xml;charset=UTF-8");
                                } else if (format.contains("rdf.ttl")) {

                                    httpServletResponse.setContentType("text/plain;charset=UTF-8");
                                } else if (format.contains("json")) {

                                    httpServletResponse.setContentType("application/json;charset=UTF-8");
                                } else if (format.contains("nquads")) {

                                    httpServletResponse.setContentType("text/plain;charset=UTF-8");
                                }

                                httpServletResponse.sendError(HttpServletResponse.SC_NOT_FOUND, "Resource <" + uri + "> not found!");
                            }
                            else {

                                String accessRights = linkedDataStorage.getAccessRights(graph, uri);

                                if (!accessRights.equals("internal") || (accessRights.equals("internal") && isUBintern) || isAuthorized) {

                                    if (format.contains("html")) {

                                        httpServletResponse.setContentType("text/html;charset=UTF-8");
                                    } else if (format.contains("rdf.xml")) {

                                        httpServletResponse.setContentType("application/rdf+xml;charset=UTF-8");
                                    } else if (format.contains("rdf.ttl")) {

                                        httpServletResponse.setContentType("text/turtle;charset=UTF-8");
                                    } else if (format.contains("json")) {

                                        httpServletResponse.setContentType("application/ld+json;charset=UTF-8");
                                    } else if (format.contains("nquads")) {

                                        httpServletResponse.setContentType("application/n-quads;charset=UTF-8");
                                    }

                                    httpServletResponse.setStatus(HttpServletResponse.SC_OK);
                                    httpServletResponse.getWriter().println(resource);
                                }
                                else {

                                    httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, config.getProperty("service.forbidden.message"));
                                }
                            }
                        }
                    }
                    else if (httpServletRequest.getPathInfo().startsWith("/search")) {

                        // Search
                        if (httpServletRequest.getParameter("q") == null) {

                            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Malformed request!");
                        }
                        else {

                            if (!format.equals("html") && !format.equals("xml") && !format.equals("json")) {

                                httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "No valid {format} requested: " + format);
                            }
                            else {

                                // Zusammenbauen der Searchquery: fq, sort, rows, start
                                Properties query = new Properties();
                                query.setProperty("q", httpServletRequest.getParameter("q"));
                                if (httpServletRequest.getParameter("start") != null && !httpServletRequest.getParameter("start").equals("")) {
                                    query.setProperty("start", httpServletRequest.getParameter("start"));
                                }
                                String fq = "";
                                if (httpServletRequest.getParameterValues("fq") != null) {
                                    for (int i = 0; i < httpServletRequest.getParameterValues("fq").length; i++) {
                                        fq += httpServletRequest.getParameterValues("fq")[i];
                                        if (i < httpServletRequest.getParameterValues("fq").length - 1) {
                                            fq += ";";
                                        }
                                    }
                                    query.setProperty("fq", fq);
                                }
                                if (httpServletRequest.getParameter("rows") != null) {
                                    query.setProperty("rows", httpServletRequest.getParameter("rows"));
                                }
                                if (httpServletRequest.getParameter("sort") != null) {
                                    query.setProperty("sort", httpServletRequest.getParameter("sort"));
                                }

                                try {

                                    String resource = linkedDataStorage.searchResource(graph, query, format, isAuthorized);

                                    if (format.contains("html")) {

                                        httpServletResponse.setContentType("text/html;charset=UTF-8");
                                    } else if (format.contains("rdf.xml")) {

                                        httpServletResponse.setContentType("application/rdf+xml;charset=UTF-8");
                                    } else if (format.contains("rdf.ttl")) {

                                        httpServletResponse.setContentType("text/turtle;charset=UTF-8");
                                    } else if (format.contains("json")) {

                                        httpServletResponse.setContentType("application/ld+json;charset=UTF-8");
                                    }

                                    if (resource == null) {

                                        httpServletResponse.sendError(HttpServletResponse.SC_NOT_FOUND, "No resources not found!");
                                    } else {

                                        httpServletResponse.setHeader("Access-Control-Allow-Origin", "*");
                                        httpServletResponse.setStatus(HttpServletResponse.SC_OK);
                                        httpServletResponse.getWriter().println(resource);
                                    }
                                } catch (Exception e) {

                                    this.logger.error(e.getMessage());
                                    httpServletResponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Failed to connect to backend! Please try again later!");
                                }
                            }
                        }
                    }
                    else if (httpServletRequest.getPathInfo().startsWith("/sparql")) {

                        if (!format.equals("html") && !format.equals("xml") && !format.equals("json")) {

                            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "No valid {format} requested: " + format);
                        }
                        else {

                            try {

                                // SPARQL
                                String resource = linkedDataStorage.sparqlQuery(graph, httpServletRequest.getParameter("q"), format, isAuthorized);

                                if (resource == null) {

                                    httpServletResponse.sendError(HttpServletResponse.SC_NOT_FOUND, "Resource not found!");
                                }
                                else {

                                    if (format.contains("html")) {

                                        httpServletResponse.setContentType("text/html;charset=UTF-8");
                                    } else if (format.contains("xml")) {

                                        httpServletResponse.setContentType("application/xml;charset=UTF-8");
                                    } else if (format.contains("json")) {

                                        httpServletResponse.setContentType("application/json;charset=UTF-8");
                                    }

                                    httpServletResponse.setStatus(HttpServletResponse.SC_OK);
                                    httpServletResponse.getWriter().println(resource);
                                }
                            } catch (Exception e) {

                                this.logger.error(e.getMessage());
                                httpServletResponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Failed to connect to backend! Please try again later!");
                            }
                        }
                    }
                    else {

                        httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "You requested a not implemented service!");
                    }
                }
            }
            catch(Exception e) {

                this.logger.error("something went wrong", e);
                httpServletResponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "something went wrong");
            }
        }
    }

    protected void doPost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        ObjectMapper mapper = new ObjectMapper();

        // CORS ORIGIN RESPONSE HEADER
        httpServletResponse.setHeader("Access-Control-Allow-Origin", config.getProperty(LDPStatics.CORS_ACCESS_CONTROL_ALLOW_ORIGIN_IDENTIFIER));

        // analyse ip range
        String ips = httpServletRequest.getHeader("X-Forwarded-For");

        boolean isTUintern = AnalyseIPRange.analyseAccessRights(ips, config.getProperty(LDPStatics.SERVICE_IPRANGE_TU_IDENTIFIER), config.getProperty(LDPStatics.SERVICE_IPRANGE_TU_EXCEPTIONS_IDENTIFIER));
        boolean isUBintern = AnalyseIPRange.analyseAccessRights(ips, config.getProperty(LDPStatics.SERVICE_IPRANGE_UB_IDENTIFIER), config.getProperty(LDPStatics.SERVICE_IPRANGE_UB_EXCEPTIONS_IDENTIFIER));

        logger.debug("[" + config.getProperty("service.name") + "] " + "Where is it from? " + httpServletRequest.getHeader("X-Forwarded-For") + ", " + isTUintern + ", " + isUBintern);

        String format = "html";
        String language = "de";
        String authorization = "";
        String contenttype = "";

        Enumeration<String> headerNames = httpServletRequest.getHeaderNames();
        while ( headerNames.hasMoreElements() ) {

            String headerNameKey = headerNames.nextElement();
            this.logger.debug("headerNameKey = " + headerNameKey + " / headerNameValue = " + httpServletRequest.getHeader(headerNameKey));

            if (headerNameKey.equals("Accept")) {

                if (httpServletRequest.getHeader(headerNameKey).contains("text/html")) {
                    format = "html";
                } else if (httpServletRequest.getHeader(headerNameKey).contains("application/rdf+xml")) {
                    format = "rdf.xml";
                } else if (httpServletRequest.getHeader(headerNameKey).contains("application/xhtml+xml")) {
                    format = "rdfa";
                } else if (httpServletRequest.getHeader(headerNameKey).contains("text/turtle")
                        || httpServletRequest.getHeader(headerNameKey).contains("application/x-turtle")
                        || httpServletRequest.getHeader(headerNameKey).contains("application/turtle")) {
                    format = "rdf.ttl";
                } else if (httpServletRequest.getHeader(headerNameKey).contains("application/ld+json")) {
                    format = "json";
                } else if (httpServletRequest.getHeader(headerNameKey).contains("application/n-quads")) {
                    format = "nquads";
                }
            }
            if (headerNameKey.equals("Authorization")) {
                authorization = httpServletRequest.getHeader( headerNameKey );
            }
            if (headerNameKey.equals("Content-Type")) {
                contenttype = httpServletRequest.getHeader(headerNameKey);
            }
        }

        this.logger.info("contenttype = " + contenttype);

        if (httpServletRequest.getParameter("format") != null) {
            format = httpServletRequest.getParameter("format");
        }

        this.logger.info("format = " + format);

        // language
        if (language != null && language.startsWith("de")) {
            language = "de";
        } else if (language != null && language.startsWith("en")) {
            language = "en";
        } else if (httpServletRequest.getParameter("lang") != null) {
            language = httpServletRequest.getParameter("lang");
        } else {
            language = this.config.getProperty(LDPStatics.SERVICE_LANGUAGE_DEFAULT_IDENTIFIER);
        }

        this.logger.info("language = " + language);

        String patronid = "";

        // if not exists token
        if (authorization.equals("")) {

            // if exists PaiaService-Cookie: read content
            Cookie[] cookies = httpServletRequest.getCookies();

            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals("PaiaService")) {

                        String value = URLDecoder.decode(cookie.getValue(), "UTF-8");
                        this.logger.info(value);
                        LoginResponse loginResponse = mapper.readValue(value, LoginResponse.class);

                        authorization = loginResponse.getAccess_token();
                        patronid = loginResponse.getPatron();

                        break;
                    }
                }
            }
        }

        this.logger.info("authorization: " + authorization);

        boolean isAuthorized = false;

        if (!authorization.equals("")) {

            if (Lookup.lookupAll(AuthorizationInterface.class).size() > 0) {

                AuthorizationInterface authorizationInterface = Lookup.lookup(AuthorizationInterface.class);
                // init Authorization Service
                authorizationInterface.init(this.config);

                try {

                    isAuthorized = authorizationInterface.isTokenValid(httpServletResponse, "data", patronid, authorization);
                }
                catch (AuthorizationException e) {

                    // TODO correct error handling
                    this.logger.error("[" + config.getProperty("service.name") + "] " + HttpServletResponse.SC_UNAUTHORIZED + "!");
                }
            } else {

                // TODO correct error handling
                this.logger.error("[" + this.config.getProperty("service.name") + "] " + HttpServletResponse.SC_INTERNAL_SERVER_ERROR + ": " + "Authorization Interface not implemented!");
            }
        }

        this.logger.debug("[" + config.getProperty("service.name") + "] " + "Authorization: " + authorization + " - " + isAuthorized);

        // ... - if not is authorized - against DFN-AAI service
        if (!isAuthorized) {

            // TODO if exists OpenAM-Session-Cookie: read content
            this.logger.debug("[" + this.config.getProperty("service.name") + "] " + "Authorization: " + authorization + " - " + isAuthorized);
        }

        // Linked Data Storage
        if (Lookup.lookupAll(LinkedDataStorage.class).size() > 0) {

            try {

                String graph = config.getProperty("storage.graph.default");

                // TODO get graph from request

                // TODO is graph valid?
                if (!this.config.getProperty("storage.graphs").contains(graph)) {

                    httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad request - graph is not valid!");
                }
                else {

                    LinkedDataStorage linkedDataStorage = Lookup.lookup(LinkedDataStorage.class);
                    // init LinkedDataStorage
                    linkedDataStorage.init(this.config);

                    if (httpServletRequest.getPathInfo().startsWith("/sparql")) {

                        if (contenttype.startsWith("application/sparql-query")) {

                            if (!format.equals("html") && !format.equals("xml") && !format.equals("json")) {

                                httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "No valid {format} requested: " + format);
                            }
                            else {

                                try {

                                    String query = httpServletRequest.getReader().lines().collect(Collectors.joining(System.lineSeparator()));

                                    if (query == null || query.equals("")) {

                                        this.logger.error(HttpServletResponse.SC_NO_CONTENT + " - No Content");
                                        httpServletResponse.sendError(HttpServletResponse.SC_NO_CONTENT, "No Content");
                                    }
                                    else {

                                        // SPARQL
                                        String resource = linkedDataStorage.sparqlQuery(graph, query, format, isAuthorized);

                                        if (resource == null) {

                                            httpServletResponse.sendError(HttpServletResponse.SC_NOT_FOUND, "Resource not found!");
                                        }
                                        else {

                                            if (format.contains("html")) {

                                                httpServletResponse.setContentType("text/html;charset=UTF-8");
                                            } else if (format.contains("xml")) {

                                                httpServletResponse.setContentType("application/xml;charset=UTF-8");
                                            } else if (format.contains("json")) {

                                                httpServletResponse.setContentType("application/json;charset=UTF-8");
                                            }

                                            httpServletResponse.setStatus(HttpServletResponse.SC_OK);
                                            httpServletResponse.getWriter().println(resource);
                                        }
                                    }
                                }
                                catch (Exception e) {

                                    this.logger.error(e.getMessage());
                                    httpServletResponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Failed to connect to backend! Please try again later!");
                                }
                            }
                        }
                        else if (contenttype.startsWith("application/sparql-update")) {
                            String data = httpServletRequest.getReader().lines().collect(Collectors.joining(System.lineSeparator()));

                            if (data == null || data.equals("")) {

                                this.logger.error(HttpServletResponse.SC_NO_CONTENT + " - No Content");
                                httpServletResponse.sendError(HttpServletResponse.SC_NO_CONTENT, "No Content");
                            }
                            else {
                                String status = linkedDataStorage.sparqlUpdate(data);

                                if (status.equals("201")) {

                                    httpServletResponse.setStatus(HttpServletResponse.SC_CREATED);
                                    httpServletResponse.getWriter().println("Created");
                                }
                                else {

                                    httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "something went wrong!");
                                }

                            }
                        }
                        else {

                            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Content-type has to be 'application/sparql-update'!");
                        }
                    }
                    else {

                        httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "You requested a not implemented service!");
                    }
                }
            }
            catch(Exception e) {

                this.logger.error("something went wrong", e);
                httpServletResponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "something went wrong");
            }
        }
        else {

            // TODO no storage configured
        }
    }
}
