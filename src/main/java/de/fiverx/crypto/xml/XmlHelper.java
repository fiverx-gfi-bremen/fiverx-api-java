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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileOutputStream;

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
            transformer.setOutputProperty(OutputKeys.ENCODING, doc.getXmlEncoding());
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(fos);
            transformer.transform(source, result);
        }
    }

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
}
