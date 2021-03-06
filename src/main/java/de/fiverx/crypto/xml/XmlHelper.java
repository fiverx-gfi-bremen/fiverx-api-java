/*
 * Copyright (c) 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.fiverx.crypto.xml;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;

/**
 * Kurzer Satz der die Klasse beschreibt.
 * <p/>
 * Detailierte Beschreibung der Klasse
 * <p/>
 * <h3>Extra-Info</h3>
 *
 * @author zeitler
 * @since v1.0
 */
public class XmlHelper {

    /**
    * Logger
    */
    private final static Logger LOG = Logger.getLogger(XmlHelper.class);


    /**
     * Translates a file with XML content to a org.w3c.dom.Document
     * @param file the file containing the xml
     * @return the Document structure of the file
     * @throws Exception
     */
    public static Document retrieveXml(File file) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        Document document = documentBuilder.parse(file);

        if (LOG.isInfoEnabled()) {
            LOG.info("retrieveXml: file=" + file + "; document=" + document + "; encoding=" + document.getXmlEncoding());
        }

        return document;
    }

    /**
     * creates a document structure from a xml-based string
     * @param doc the string containing the xml structure
     * @return the document structure of the xml.
     * @throws Exception
     */
    public static Document retrieveXml(String doc) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(doc.getBytes());
        // comment:bz: Encoding hardcoded! Und warum UTF-8 ?
        Reader reader = new InputStreamReader(inputStream,"UTF-8");
        InputSource is = new InputSource(reader);
        is.setEncoding("UTF-8");
        Document document = documentBuilder.parse(is);

        if (LOG.isInfoEnabled()) {
            LOG.info("retrieveXml: doc=" + doc + "; document=" + document + "; encoding=" + document.getXmlEncoding());
        }

        return document;
    }

    /**
     * Writes a xml document to a file.
     * @param doc the document that shall be written to the given file
     * @param file the file the document structure is written to
     * @param withNamespaces tells if the namespaces should be respected.
     * @throws Exception
     */
    public static void writeDocToFile(Document doc, File file, boolean withNamespaces) throws Exception {
        if (file.exists()) {
            boolean deleted = file.delete();

            if (LOG.isDebugEnabled()) {
                LOG.debug("writeDocToFile: file deleted! file=" + file + "; deleted=" + deleted);
            }
        }

        try (FileOutputStream fos = new FileOutputStream(file)) {
            TransformerFactory factory = TransformerFactory.newInstance();
            Transformer transformer = factory.newTransformer();
            String xmlEncoding = doc.getXmlEncoding();
            transformer.setOutputProperty(OutputKeys.ENCODING, xmlEncoding);
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(fos);
            transformer.transform(source, result);
            if (LOG.isInfoEnabled()) {
              LOG.info("writeDocToFile: xml file written! file=" + file + "; encoding=" + xmlEncoding);
            }
        }
    }

    /**
     * Makes a copy of an xml-document.
     * @param doc the document that should be copied.
     * @return the copied document.
     */
    public static Document cloneDocument(Document doc) {
        try {
            TransformerFactory tfactory = TransformerFactory.newInstance();
            Transformer tx   = tfactory.newTransformer();
            DOMSource source = new DOMSource(doc);
            DOMResult result = new DOMResult();
            tx.transform(source,result);
            Document clone = (Document) result.getNode();

            if (LOG.isDebugEnabled()) {
              LOG.debug("cloneDocument: dom cloned! source=" + doc + "; clone=" + clone);
            }

            return clone;
        } catch (TransformerException e) {
            throw new IllegalStateException("Cloning dom failed!");
        }
    }

    /**
     * translates a document to a string variable
     * @param document the document that should be converted to a string
     * @return the converted string from the xml document.
     * @throws TransformerException
     */
    public static String documentToString (Document document) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(writer));
        return writer.getBuffer().toString().replaceAll("\n|\r", "");
    }

    /**
     * translates an inner element of a document to a string.
     * @param element the element that should be translated to a string
     * @return the converted string of the element
     * @throws TransformerException
     */
    public static String elementToString (Element element) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(element), new StreamResult(writer));
        return writer.getBuffer().toString().replaceAll("\n|\r", "");
    }
}
