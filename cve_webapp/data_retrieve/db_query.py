import os
from datetime import datetime, time
import psycopg2

def db_connection():
    conn = psycopg2.connect(
        database="nvd_db",
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

def query_cve_summary(table_name):
    sql_query = "SELECT cve_id, summary, published, last_modified, score, num_of_affected_products FROM %s" % (table_name)
    print sql_query

    temp_data = []
    cur, conn = db_connection()
    cur.execute(sql_query)
    rows = cur.fetchall()
    for item in rows:
        cve_id = item[0]
        summary = item[1]
        published = item[2]
        last_modified = item[3]
        score = item[4]
        num_of_affected_products = item[5]

        json_data = ({
            "cve_id": cve_id.strip(),
            "summary": summary,
            "published": str(published),
            "last_modified": str(last_modified),
            "score": score,
            "num_of_affected_products": num_of_affected_products
        })
        temp_data.append(json_data)
    conn.close()
    return temp_data

def query_cve_full_details(table_name, cve_id):
    sql_query = """SELECT cve_id, summary, score, num_of_affected_products,
                access_vector, access_complexity, authentication, confidentiality_impact, integrity_impact, source
                FROM nvdcve_details_2005 WHERE cve_id = %s
                 INNER JOIN nvdcve_affected_products_2005
                  on nvdcve_details_2005.cve_id = nvdcve_affected_products_2005.cve_id
                  INNER JOIN nvdcve_references_2005
                  on nvdcve_affected_products_2005.cve_id = nvdcve_references_2005.cve_id""" % (table_name, cve_id)
    print sql_query

    temp_data = []
    cur, conn = db_connection()
    cur.execute(sql_query)
    rows = cur.fetchall()
    for item in rows:
        cve_id = item[0]
        summary = item[1]
        published = item[2]
        last_modified = item[3]
        score = item[4]
        num_of_affected_products = item[5]

        json_data = ({
            "cve_id": cve_id.strip(),
            "summary": summary,
            "published": str(published),
            "last_modified": str(last_modified),
            "score": score,
            "num_of_affected_products": num_of_affected_products
        })
        temp_data.append(json_data)
    conn.close()
    return temp_data
table_name = 'nvdcve_details_2002'

query_cve_summary(table_name)




