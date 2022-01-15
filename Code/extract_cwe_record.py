import ast
import json
import os
import time
import xml.etree.ElementTree as et
import pandas as pd
from io import BytesIO
from urllib.request import urlopen
from zipfile import ZipFile
from pandas import json_normalize

import configuration as cf

# --------------------------------------------------------------------------------------------------------


def extract_cwe():
    """
    obtains the table of CWE categories from NVD.nist.gov site
    :return df_CWE: dataframe of CWE category table
    
    从NVD.nist.gov网站获取CWE分类表
    :返回 df_CWE: CWE分类表的数据帧
    """
    # 下载-解压-解析xml为xtree
    if os.path.isdir(cf.DATA_PATH + "cwec_v4.6.xml"):
        cf.logger.info("Reusing the CWE XML file that is already in the directory")
        xtree = et.parse(cf.DATA_PATH + "cwec_v4.6.xml")
    else: 
        cwe_csv_url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
        cwe_zip = ZipFile(BytesIO(urlopen(cwe_csv_url).read()))
        cwefile = cwe_zip.extract("cwec_v4.6.xml", cf.DATA_PATH)
        xtree = et.parse(cwefile)
        time.sleep(2)

    # loop: 
    xroot = xtree.getroot()
    cat_flag = 0
    rows = []

    # 只取weaknesses,Categories,Views; 不取External_References
    for parents in xroot[0:2]:  # taking only 0, 1 and 2 (index 0 is for weaknesses, 1 for Categories, 2 for Views, 3 for External_References)
        # 对于weaknesses: 提取cwe_id,cwe_name,description即为node[0],extended_description为''
        # 对于Categories: 提取cwe_id,cwe_name,Summary/description即为node[0],extended_description即为node[1]包含了所有的member
        # 对于Views:      提取cwe_id,cwe_name,略
        for node in parents:
            cwe_id = 'CWE-' + str(node.attrib['ID'])
            cwe_name = node.attrib['Name'] if node.attrib['Name'] is not None else None
            description = node[0].text if node[0].text is not None else None
            extended_des = et.tostring(node[1], encoding="unicode", method='text') if cat_flag != 1 else ''
            url = 'https://cwe.mitre.org/data/definitions/' + str(node.attrib['ID']).strip() + '.html' if int(node.attrib['ID']) > 0 else None
            is_cat = True if cat_flag == 1 else False

            rows.append({
                'cwe_id': cwe_id,
                'cwe_name': cwe_name,
                'description': description,
                'extended_description': extended_des,
                'url': url,
                'is_category': is_cat,
            })
            
        cat_flag += 1

    # explicitly adding three CWEs that are not in the xml file
    # 显式地添加三个不在xml文件中的cwe
    rows.append({
        'cwe_id': 'NVD-CWE-noinfo',
        'cwe_name': 'Insufficient Information',
        'description': 'There is insufficient information about the issue to classify it; details are unkown or unspecified.',
        'extended_description': 'Insufficient Information',
        'url': 'https://nvd.nist.gov/vuln/categories',
        'is_category': False
    })
    rows.append({
        'cwe_id': 'NVD-CWE-Other',
        'cwe_name': 'Other',
        'description': 'NVD is only using a subset of CWE for mapping instead of the entire CWE, and the weakness type is not covered by that subset.',
        'extended_description': 'Insufficient Information',
        'url': 'https://nvd.nist.gov/vuln/categories',
        'is_category': False
    })

    # 转成DataFrame,并drop重复的cwe_id
    df_cwe = pd.DataFrame.from_dict(rows)
    df_cwe = df_cwe.drop_duplicates(subset=['cwe_id']).reset_index(drop=True)
    return df_cwe


def parse_cwes(str1):
    """
    Converts string to list.
    """
    lst = ast.literal_eval(str1)
    lst = [x.strip() for x in lst]
    return lst


def add_cwe_class(problem_col):
    """
    returns CWEs of the CVE.
    """
    cwe_classes = []
    for p in problem_col:
        des = str(p).replace("'", '"')
        des = json.loads(des)
        for cwes in json_normalize(des)["description"]:  # for every cwe of each cve.
            if len(cwes) != 0:
                cwe_classes.append([cwe_id for cwe_id in json_normalize(cwes)["value"]])
            else:
                cwe_classes.append(["unknown"])

    assert len(problem_col) == len(cwe_classes), \
        "Sizes are not equal - Problem occurred while fetching the cwe classification records!"
    return cwe_classes
