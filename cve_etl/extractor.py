import urllib2
import re
import requests
from lxml import etree
import zipfile
import psycopg2
import glob
from psycopg2.extensions import AsIs

"""Initilaize DB connection"""
def db_connection():
    conn = psycopg2.connect(
        database="scratch",
        user="postgres",
        password="postgres",
        host="localhost",
        port='5432')

    try:
        cur = conn.cursor()

    except OperationalError:
        connected = False
    else:
        connected = True

    if connected == False:
        print "Connection error"
    else:
        print "DB Connected"
    return cur, conn

"""Create table for Reference data"""
def create_references_table(cur, conn, table_name):
    print "--------------------------------------------"

    statement = """CREATE TABLE IF NOT EXISTS %s (
                                                  id SERIAL PRIMARY KEY,
                                                  cve_id CHARACTER(30),
                                                  url TEXT);""" % (table_name)
    print statement
    cur.execute(statement)
    conn.commit()
    print "--------------------------------------------"
    print "TABLE", table_name, "CREATED"

"""Create table for Number of Affected Products data"""
def create_affected_products_table(cur, conn, table_name):
    print "--------------------------------------------"

    statement = """CREATE TABLE IF NOT EXISTS %s (id SERIAL PRIMARY KEY, cve_id CHARACTER(30), product TEXT);""" % (
        table_name)
    print statement
    cur.execute(statement)
    conn.commit()
    print "--------------------------------------------"
    print "TABLE", table_name, "CREATED"

"""Create table for CVE details/elements"""
def create_cve_details_table(cur, conn, table_name):
    print "--------------------------------------------"

    statement = """CREATE TABLE IF NOT EXISTS %s (id SERIAL PRIMARY KEY,
                                                  cve_id CHARACTER(30),
                                                  summary TEXT,
                                                  published TIMESTAMP,
                                                  last_modified TIMESTAMP,
                                                  score DECIMAL ,
                                                  num_of_affected_products INTEGER ,
                                                  access_vector CHARACTER (20),
                                                  access_complexity CHARACTER (20),
                                                  authentication CHARACTER (20),
                                                  confidentiality_impact CHARACTER (20),
                                                  integrity_impact CHARACTER (20),
                                                  source TEXT,
                                                  generated_on TIMESTAMP );""" % (table_name)
    print statement
    cur.execute(statement)
    conn.commit()
    print "--------------------------------------------"
    print "TABLE", table_name, "CREATED"

"""Main ETL loader, recieves extracted XML files from disk then load selected elements in DB tables"""
def load_xml_to_db(cur, conn, xml_file, cve_table, affected_table, ref_table):
    dom = etree.parse(xml_file)
    root = dom.getroot()
    for i in range(len(root)):
        affected_products = []
        ref_url_list = []

        for node in root[i].iter():
            if 'summary' in node.tag:
                summary = node.text
            if 'cve-id' in node.tag:
                cve_id = node.text.strip()
            if 'published-datetime' in node.tag:
                published = node.text
            if 'last-modified-datetime' in node.tag:
                last_modified = node.text
            if 'score' in node.tag:
                score = node.text
            if 'product' in node.tag:
                affected_products.append(node.text)
            if 'access-vector' in node.tag:
                access_vector = node.text
            if 'access-complexity' in node.tag:
                access_complexity = node.text
            if 'authentication' in node.tag:
                authentication = node.text
            if 'confidentiality-impact' in node.tag:
                confidentiality_impact = node.text
            if 'integrity-impact' in node.tag:
                integrity_impact = node.text
            if 'availability-impact' in node.tag:
                availability_impact = node.text
            if 'source' in node.tag:
                source = node.text
            if 'generated-on-datetime' in node.tag:
                generated_on_datetime = node.text
            if 'references' in node.tag:
                for ref in node.getchildren():
                    if 'reference' in ref.tag:
                        ref_url_list.append(ref.attrib.values()[0])
        print '%s: %d' %('Inserting Node', i+1), 'out of:', len(root), "INSERTING RECORDS FOR:", cve_id
        num_of_products = len(affected_products)
        cveTable_insert = """INSERT INTO %s (cve_id,summary,published,last_modified, score, num_of_affected_products, access_vector, access_complexity, authentication, confidentiality_impact, integrity_impact, source, generated_on)
                              VALUES (%s, %s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s)"""
        data =  (AsIs(cve_table), cve_id.strip(), summary, published, last_modified, score, num_of_products, access_vector, access_complexity, authentication,confidentiality_impact, integrity_impact, source, generated_on_datetime)
        # print cveTable_insert
        cur.execute(cveTable_insert, data)
        conn.commit()
        for product in affected_products:
            affectedprodTable_insert = """INSERT INTO %s (cve_id, product) VALUES ('%s','%s')""" % (
                    affected_table, cve_id, product)
            cur.execute(affectedprodTable_insert)
            conn.commit()
        for reference in ref_url_list:
            referencesTable_insert = """INSERT INTO %s (cve_id, url) VALUES ('%s','%s')""" % (
                ref_table, cve_id, reference)
            cur.execute(referencesTable_insert)
            conn.commit()

def file_grabber():
    raw_files_list = []
    for file in glob.glob('*/*.zip'):
        raw_files_list.append(file)
    return raw_files_list

def get_xml_files():
    raw_files_list = []
    for file in glob.glob('*/*.xml'):
        raw_files_list.append(file)
    return raw_files_list

def unzip_all_files(raw_files):
    for file in raw_files:
        zip_ref = zipfile.ZipFile(file, 'r')
        zip_ref.extractall('unzipped_files')
        zip_ref.close()
        print file, "was successfully extracted."

def main():
    cur, conn = db_connection()
    create_cve_details_table(cur, conn, 'nvdcve_modified_details')
    create_references_table(cur, conn, 'nvdcve_modified_references')
    create_affected_products_table(cur, conn, 'nvdcve_modified_affected_products')

    create_cve_details_table(cur, conn, 'nvdcve_recent_details')
    create_references_table(cur, conn, 'nvdcve_recent_references')
    create_affected_products_table(cur, conn, 'nvdcve_recent_affected_products')

    create_cve_details_table(cur, conn, 'nvdcve_details')
    create_affected_products_table(cur, conn, 'nvdcve_affected_products')
    create_references_table(cur, conn, 'nvdcve_references')

    raw_files = file_grabber()
    unzip_all_files(raw_files)
    xml_list = get_xml_files()
    for file_name in xml_list:
        if 'mod' in str(file_name):
            load_xml_to_db(cur, conn, file_name, 'nvdcve_modified_details', 'nvdcve_modified_affected_products',
                           'nvdcve_modified_references')

        if 'rece' in str(file_name):
            load_xml_to_db(cur, conn, file_name, 'nvdcve_recent_details', 'nvdcve_recent_affected_products',
                           'nvdcve_recent_references')
        else:
            load_xml_to_db(cur, conn, file_name, 'nvdcve_details', 'nvdcve_affected_products', 'nvdcve_references')
    # close connection
    cur.close()
    conn.close()



"""FAILED AUTO DOWNLOADER"""

# web = 'https://nvd.nist.gov/download.cfm'
# br = Browser()
# br.set_handle_robots(False)
# br.set_handle_equiv(False)
# br.addheaders = [('User-agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36')]
# page = br.open(web)
# htmlcontent = page.read()
# print htmlcontent
# paragraphs = re.findall(r'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-(.*?)\.zip',str(respData))
# for eachP in paragraphs:
#     print(eachP)

#####
# Main entry point
#####
if (__name__ == "__main__"):
    main()
