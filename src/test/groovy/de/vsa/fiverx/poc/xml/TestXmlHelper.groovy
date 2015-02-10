/*
 * Copyright (c) 2015 VSA Gmbh
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

package de.vsa.fiverx.poc.xml

import de.vsa.fiverx.poc.ConfigHolder
import groovy.util.logging.Log4j
import org.junit.Before
import org.junit.Test
import org.w3c.dom.Document

import static org.junit.Assert.assertArrayEquals
import static org.junit.Assert.assertTrue
import static org.junit.Assert.fail

/**
 * Created by zeitler on 19.01.15.
 */


@Log4j
class TestXmlHelper {

    def source = new File('src/test/resources/data/purchase.xml')

    def destination = new File('build/tmp/written.xml')

    @Before
    public void setUp() throws Exception {
        if (destination.exists()) {
            assertTrue destination.delete()
        }
        destination.parentFile.mkdirs()
    }

    @Test
    public void testXmlEncoding() {
        Document doc = XmlHelper.retrieveXml(source)

        XmlHelper.writeDocToFile(doc, destination, true)

        checkBookingEncoding(destination)
    }

    public static void checkBookingEncoding(File file) {
        // implicit test
        List<String> lines = file.text.readLines()
        assertTrue lines[0].contains(ConfigHolder.Encoding.configured)

        //explicit test
        def itemExists = false
        lines.each {
            if (it.contains('<Item>')) {
                itemExists = true
                byte[] line = it.trim().getBytes(ConfigHolder.Encoding.configured)
                //text = "<Item>book Über Döner und Dürüm</Item>" in ISO-8859-15
                byte[] text = [60, 73, 116, 101, 109, 62, 98, 111, 111, 107, 32, 63, 98, 101, 114, 32, 68, 63, 110, 101, 114, 32, 117, 110, 100, 32, 68, 63, 114, 63, 109, 60, 47, 73, 116, 101, 109, 62]

                assertArrayEquals(line, text)
                return
            }
        }
        if (!itemExists) {
            fail '<Item> not found!'
        }
    }

}
