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

/**
 * Linked Data Platform Resource Endpoint
 *
 * @author Dipl.-Math. Hans-Georg Becker, M.L.I.S. (UB Dortmund)
 * @version 2015-08-08
 *
 */
public class LinkedDataPlatformResourceEndpoint extends HttpServlet {

    public static final  String     UTF_8  = "UTF-8";
    private static       Properties config = new Properties();

    private static Logger logger = Logger.getLogger(LinkedDataPlatformResourceEndpoint.class.getName());

    public LinkedDataPlatformResourceEndpoint(String conffile) {

        // Init properties
        try {

            try (InputStream inputStream = new FileInputStream(conffile)) {

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, UTF_8))) {

                    config.load(reader);
                }
            }
        }
        catch (IOException e) {

            logger.error("something went wrong", e);
            logger.error(String.format("FATAL ERROR: Could not read '%s'!", conffile));
        }

        // init logger
        PropertyConfigurator.configure(config.getProperty(LDPStatics.SERVICE_LOG4J_CONF_IDENTIFIER));

        final String serviceName = config.getProperty(LDPStatics.SERVICE_NAME_IDENTIFIER);

        logger.info(String.format("[%s] Starting '" + LinkedDataPlatformResourceEndpoint.class.getName() + "' ...", serviceName));
        logger.info(String.format("[%s] conf-file = %s", serviceName, conffile));

        final String log4jConfFile = config.getProperty(LDPStatics.SERVICE_LOG4J_CONF_IDENTIFIER);

        logger.info(String.format("[%s] log4j-conf-file = %s", serviceName, log4jConfFile));
    }

    protected void doOptions(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        response.setHeader("Access-Control-Allow-Methods", config.getProperty(LDPStatics.CORS_ACCESS_CONTROL_ALLOW_METHODS_IDENTIFIER));
        response.addHeader("Access-Control-Allow-Headers", config.getProperty(LDPStatics.CORS_ACCESS_CONTROL_ALLOW_HEADERS_IDENTIFIER));
        response.setHeader("Access-Control-Allow-Origin", config.getProperty(LDPStatics.CORS_ACCESS_CONTROL_ALLOW_ORIGIN_IDENTIFIER));
        response.setHeader("Accept", config.getProperty(LDPStatics.CORS_ACCEPT_IDENTIFIER));

        response.getWriter().println();
    }

    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        ObjectMapper mapper = new ObjectMapper();

        // CORS ORIGIN RESPONSE HEADER
        httpServletResponse.setHeader("Access-Control-Allow-Origin", config.getProperty(LDPStatics.CORS_ACCESS_CONTROL_ALLOW_ORIGIN_IDENTIFIER));

        // analyse ip range
        String ips = httpServletRequest.getHeader("X-Forwarded-For");

        boolean isTUintern = AnalyseIPRange.analyseAccessRights(ips, config.getProperty(LDPStatics.SERVICE_IPRANGE_TU_IDENTIFIER), config.getProperty(LDPStatics.SERVICE_IPRANGE_TU_EXCEPTIONS_IDENTIFIER));
        boolean isUBintern = AnalyseIPRange.analyseAccessRights(ips, config.getProperty(LDPStatics.SERVICE_IPRANGE_UB_IDENTIFIER), config.getProperty(LDPStatics.SERVICE_IPRANGE_UB_EXCEPTIONS_IDENTIFIER));

        logger.debug("[" + config.getProperty("service.name") + "] " + "Where is it from? " + httpServletRequest.getHeader("X-Forwarded-For") + ", " + isTUintern + ", " + isUBintern);

        // analyse request header
        String format = "html";
        String profile = this.config.getProperty("storage.graph.default");
        String language = "de";
        String authorization = "";

        Enumeration<String> headerNames = httpServletRequest.getHeaderNames();
        while (headerNames.hasMoreElements()) {

            String headerNameKey = headerNames.nextElement();
            logger.debug("headerNameKey = " + headerNameKey + " / headerNameValue = " + httpServletRequest.getHeader(headerNameKey));

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
                authorization = httpServletRequest.getHeader(headerNameKey);
            }
            if (headerNameKey.equals("Accept-Language")) {
                language = httpServletRequest.getHeader(headerNameKey);
            }
        }

        if (httpServletRequest.getParameter("format") != null) {
            format = httpServletRequest.getParameter("format");
        }

        this.logger.info("format = " + format);

        if (httpServletRequest.getParameter("profile") != null) {
            profile = httpServletRequest.getParameter("profile");
        }

        this.logger.info("profile = " + profile);

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

        logger.info("authorization: " + authorization);

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

                String graph = profile;

                // TODO get graph from request

                // TODO is graph valid?
                if (!config.getProperty("storage.graphs").contains(graph)) {

                    httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad request - graph is not valid!");
                }
                else {

                    LinkedDataStorage linkedDataStorage = Lookup.lookup(LinkedDataStorage.class);
                    // init LinkedDataStorage
                    linkedDataStorage.init(config);

                    logger.info("PathInfo: " + httpServletRequest.getPathInfo());
                    String[] path = httpServletRequest.getPathInfo().split("/");

                    if (path[path.length - 1].startsWith("about-meta")) {

                        try {

                            format = path[path.length - 1].split("about-meta\\.")[1];
                        }
                        catch (ArrayIndexOutOfBoundsException e) {

                            // es bleibt das Format des Header gültig
                        }

                        logger.info("format = " + format);

                        if (!format.contains("html") && !format.contains("rdf.xml") && !format.contains("rdf.ttl") && !format.contains("json") && !format.contains("nquads")) {

                            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "No valid {format} requested: " + format);

                        }
                        else {

                            String uri = config.getProperty("resource.baseurl") + httpServletRequest.getServletPath() + httpServletRequest.getPathInfo().split("-meta")[0];

                            String resource = linkedDataStorage.getResource(graph, uri, format, isAuthorized);

                            if (resource == null) {

                                httpServletResponse.sendError(HttpServletResponse.SC_NOT_FOUND, "Resource not found!");
                            }
                            else {

                                String accessRights = linkedDataStorage.getAccessRights(graph, uri);

                                if (!accessRights.equals("internal") || (accessRights.equals("internal") && isUBintern) || isAuthorized) {

                                    if (format.contains("html")) {

                                        httpServletResponse.setContentType("text/html;charset=UTF-8");
                                    }
                                    else if (format.contains("rdf.xml")) {

                                        httpServletResponse.setContentType("application/rdf+xml;charset=UTF-8");
                                    }
                                    else if (format.contains("rdf.ttl")) {

                                        httpServletResponse.setContentType("text/turtle;charset=UTF-8");
                                    }
                                    else if (format.contains("json")) {

                                        httpServletResponse.setContentType("application/ld+json;charset=UTF-8");
                                    }
                                    else if (format.contains("nquads")) {

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
                    else if (path[path.length - 1].startsWith("about")) {

                        try {

                            format = path[path.length - 1].split("about\\.")[1];
                        }
                        catch (ArrayIndexOutOfBoundsException e) {

                            // es bleibt das Format des Header gültig
                        }

                        logger.info("format = " + format);

                        if (!format.contains("html") && !format.contains("rdf.xml") && !format.contains("rdf.ttl") && !format.contains("json") && !format.contains("nquads")) {

                            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "No valid {format} requested: " + format);
                        }
                        else {

                            String[] tmp = httpServletRequest.getPathInfo().split("/about");

                            String uri = config.getProperty("resource.baseurl") + httpServletRequest.getServletPath() + tmp[0];
                            if (tmp.length == 2 && !tmp[1].startsWith(".")) {

                                uri += "/about";
                            }
                            logger.debug(tmp.length + " / uri: " + uri);

                            String accessRights = linkedDataStorage.getAccessRights(graph, uri);

                            if (accessRights.equals("public")
                                    || (accessRights.equals("internal") && isUBintern) || isAuthorized) {

                                String resource = linkedDataStorage.getResource(graph, uri, format, isAuthorized);

                                if (resource == null) {

                                    httpServletResponse.sendError(HttpServletResponse.SC_NOT_FOUND, "Resource not found!");
                                } else {

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

                                    httpServletResponse.setHeader("Link", "<" + uri + "/about-meta>; rel=meta");
                                    httpServletResponse.setStatus(HttpServletResponse.SC_OK);
                                    httpServletResponse.getWriter().println(resource);
                                }
                            } else {

                                httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, config.getProperty("service.forbidden.message"));
                            }
                        }
                    } else {

                        if (!format.equals("html") && !format.equals("rdfa") && !format.equals("rdf.xml") && !format.equals("rdf.ttl") && !format.equals("json") && !format.equals("nquads")) {

                            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "No valid {format} requested: " + format);
                        } else {

                            // HTTP 303 See Other mit about.{format} + ggf. .{lang}
                            String uri = config.getProperty("resource.baseurl");

                            if (Boolean.parseBoolean(config.getProperty("service.istest"))) {

                                uri = "http://" + httpServletRequest.getServerName() + ":" + httpServletRequest.getServerPort();
                            }

                            uri += httpServletRequest.getServletPath() + httpServletRequest.getPathInfo() + "/about";

                            logger.debug("303-URI: " + uri);

                            httpServletResponse.setStatus(HttpServletResponse.SC_SEE_OTHER);
                            httpServletResponse.setHeader("Location", uri);
                            httpServletResponse.setHeader("Vary", "Accept");
                            httpServletResponse.getWriter().println("");
                        }
                    }
                }
            }
            catch(Exception e) {

                logger.error("something went wrong", e);
                httpServletResponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "something went wrong");
            }
        }
        else {

            // TODO no storage configured
        }
    }
}
