# Obtaining and processing CVE json **files**
# The code is to download nvdcve zip files from NIST since 2002 to the current year,
# unzip and append all the JSON files together,
# and extracts all the entries from json files of the projects.

# 获取和处理CVE json **文件**
# 代码是从NIST下载nvdcve zip文件从2002年到今年，
# 解压并附加所有JSON文件，
# 并从项目的json文件中提取所有条目。

import datetime
import json
import os
import re
from io import BytesIO
import pandas as pd
import requests
from pathlib import Path
from zipfile import ZipFile
from pandas import json_normalize

from extract_cwe_record import add_cwe_class,  extract_cwe
import configuration as cf
import database as db

# ---------------------------------------------------------------------------------------------------------------------

# 从NIST下载nvdcve zip文件
urlhead = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'
urltail = '.json.zip'
initYear = 2002
currentYear = datetime.datetime.now().year

# Consider only current year CVE records when sample_limit>0 for the simplified example.
if cf.SAMPLE_LIMIT > 0:
    initYear = currentYear

df = pd.DataFrame()

# cve的列
ordered_cve_columns = ['cve_id', 'published_date', 'last_modified_date', 'description', 'nodes', 'severity',
                       'obtain_all_privilege', 'obtain_user_privilege', 'obtain_other_privilege',
                       'user_interaction_required',
                       'cvss2_vector_string', 'cvss2_access_vector', 'cvss2_access_complexity', 'cvss2_authentication',
                       'cvss2_confidentiality_impact', 'cvss2_integrity_impact', 'cvss2_availability_impact',
                       'cvss2_base_score',
                       'cvss3_vector_string', 'cvss3_attack_vector', 'cvss3_attack_complexity',
                       'cvss3_privileges_required',
                       'cvss3_user_interaction', 'cvss3_scope', 'cvss3_confidentiality_impact',
                       'cvss3_integrity_impact',
                       'cvss3_availability_impact', 'cvss3_base_score', 'cvss3_base_severity',
                       'exploitability_score', 'impact_score', 'ac_insuf_info',
                       'reference_json', 'problemtype_json']

# cwe的列
cwe_columns = ['cwe_id', 'cwe_name', 'description', 'extended_description', 'url', 'is_category']

# ---------------------------------------------------------------------------------------------------------------------


def rename_columns(name):
    """
    converts the other cases of string to snake_case, and further processing of column names.
    将字符串的其他情况转换为snake_case，并进一步处理列名。
    """
    name = name.split('.', 2)[-1].replace('.', '_')
    name = re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()
    name = name.replace('cvss_v', 'cvss').replace('_data', '_json').replace('description_json', 'description')
    return name


def preprocess_jsons(df_in):
    """
    Flattening CVE_Items and removing the duplicates
    :param df_in: merged dataframe of all years json files
    
    平坦CVE_Items并删除副本
    :param df_in:合并所有年份json文件作为DataFrame
    
    参考: JSON文件格式
        "CVE_data_type" : "CVE",
        "CVE_data_format" : "MITRE",
        "CVE_data_version" : "4.0",
        "CVE_data_numberOfCVEs" : "40",
        "CVE_data_timestamp" : "2022-01-08T08:00Z",
        "CVE_Items" : [略]
    """
    # 报告: 开始平坦CVE_Items并删除副本
    cf.logger.info('Flattening CVE_Items and removing the duplicates...')
    
    # 只提取CVE_Items,抛弃其他
    cve_items = json_normalize(df_in['CVE_Items'])
    df_cve = pd.concat([df_in.reset_index(), cve_items], axis=1)

    # Removing all CVE entries which have null values in reference-data at [cve.references.reference_data] column
    # 删除所有在[cve.references.reference_data] column的reference-data中有空值的CVE条目
    # TODO 为什么要删除reference-data中有空值的CVE条目?
    df_cve = df_cve[df_cve['cve.references.reference_data'].str.len() != 0]

    # Re-ordering and filtering some redundant and unnecessary columns 重新排序和过滤一些冗余和不必要的列
    # 重命名: 'cve.CVE_data_meta.ID' => 'cve_id'
    df_cve = df_cve.rename(columns={'cve.CVE_data_meta.ID': 'cve_id'})
    df_cve = df_cve.drop(
        # 删除列
        labels=[
            'index',
            'CVE_Items',
            'cve.data_type',
            'cve.data_format',
            'cve.data_version',
            'CVE_data_type',
            'CVE_data_format',
            'CVE_data_version',
            'CVE_data_numberOfCVEs',
            'CVE_data_timestamp',
            'cve.CVE_data_meta.ASSIGNER',
            'configurations.CVE_data_version',
            'impact.baseMetricV2.cvssV2.version',
            'impact.baseMetricV2.exploitabilityScore',
            'impact.baseMetricV2.impactScore',
            'impact.baseMetricV3.cvssV3.version',
        ], axis=1, )

    # renaming the column names
    # 将字符串的其他情况转换为snake_case，并进一步处理列名。
    df_cve.columns = [rename_columns(i) for i in df_cve.columns]

    # ordering the cve columns 对cve列排序
    df_cve = df_cve[ordered_cve_columns]

    return df_cve


def import_cves():
    """
    gathering CVE records by processing JSON files.
    通过处理JSON文件收集CVE和CWE记录
    """
    # ----------------------收集CVE表-----------------------------------------------------------------
    cf.logger.info('-' * 70)
    
    if db.table_exists('cve'):  # 若已存在cve表
        cf.logger.warning('The cve table already exists, loading and continuing extraction...')
        # df_cve = pd.read_sql(sql="SELECT * FROM cve", con=db.conn)
        
    else:   # 若不存在cve表: 逐年下载并解压
        # loop: 年份从2002到当前年份
        for year in range(initYear, currentYear + 1):
            extract_target = 'nvdcve-1.1-' + str(year) + '.json'    # 需要提取的目标文件
            zip_file_url = urlhead + str(year) + urltail    # 需要下载的压缩文件名

            # Check if the directory already has the json file or not ? 
            if os.path.isfile(Path(cf.DATA_PATH) / 'json' / extract_target): # 目录已经有json文件
                '''"/"表示文件夹层级'''
                cf.logger.warning('Reusing', year, 'CVE json file that was downloaded earlier...')
                json_file = Path(cf.DATA_PATH) / 'json' / extract_target
            else:# 目录没有json文件
                # url_to_open = urlopen(zip_file_url, timeout=10)
                r = requests.get(zip_file_url) # 创建get
                z = ZipFile(BytesIO(r.content))  # BytesIO keeps the file in memory 下载暂存在内存中
                json_file = z.extract(extract_target, Path(cf.DATA_PATH) / 'json') # 解压到目标位置

            # 打开json文件,转成list后加入DataFrame
            with open(json_file) as f:  
                '''JSON.load(): 解码 JSON 数据,返回 Python 字段的数据类型'''
                yearly_data = json.load(f) 
                if year == initYear:  # initialize the df_methods by the first year data 用第一年的数据初始化df_methods
                    df_cve = pd.DataFrame(yearly_data)
                else:  # 直接append
                    df_cve = df_cve.append(pd.DataFrame(yearly_data))
                cf.logger.info(str(year), 'CVE json file has been merged')

        # [调用] 平坦CVE_Items并删除副本
        df_cve = preprocess_jsons(df_cve)
        # 所有元素全部转成str
        '''panda DataFrame.applymap: 对所有单元格应用某函数'''
        df_cve = df_cve.applymap(str) # 此处的str为构造函数
        # [断言] cve_id必须unique
        assert df_cve.cve_id.is_unique, 'Primary keys are not unique in cve records!'
        # 完成! 写入cve table
        '''pandas DataFrame.to_sql: 写入数据库'''
        df_cve.to_sql(name="cve", con=db.conn, if_exists="replace", index=False)
        cf.logger.info('All CVEs have been merged into the cve table')
        cf.logger.info('-' * 70)

        # ----------------收集cwe表-------------------------------------------------------------------------------

        # 从cwe.xml中提取信息,转成DataFrame
        df_cwes = extract_cwe()
        
        # fetching CWE associations to CVE records
        # 获取CWE关联到CVE记录
        cf.logger.info('Adding CWE category to CVE records...')
        df_cwes_class = df_cve[['cve_id', 'problemtype_json']].copy() # copy cve的列
        df_cwes_class['cwe_id'] = add_cwe_class(df_cwes_class['problemtype_json'].tolist())  # list of CWE-IDs' portion

        # exploding the multiple CWEs list of a CVE into multiple rows.
        # 将一个CVE的多个cwe列表分解为多个行
        '''pandas assign: 为DataFrame分配新的列'''
        '''pandas explode: 将类似列表的每个元素转换为一行，从而复制索引值。'''
        df_cwes_class = df_cwes_class.assign(
            cwe_id=df_cwes_class.cwe_id).explode('cwe_id').reset_index()[['cve_id', 'cwe_id']]
        '''pandas drop_duplicates: 去除特定列下面的重复行。返回DataFrame格式的数据。'''
        df_cwes_class = df_cwes_class.drop_duplicates(subset=['cve_id', 'cwe_id']).reset_index(drop=True)
        df_cwes_class['cwe_id'] = df_cwes_class['cwe_id'].str.replace('unknown', 'NVD-CWE-noinfo')

        # logger输出没有联系上cwe的cve
        no_ref_cwes = set(list(df_cwes_class.cwe_id)).difference(set(list(df_cwes.cwe_id)))
        if len(no_ref_cwes) > 0:
            cf.logger.debug('List of CWEs from CVEs that are not associated to cwe table are as follows:- ')
            cf.logger.debug(no_ref_cwes)

        # Applying the assertion to cve-, cwe- and cwe_classification table.
        # 对cve-、cwe-和cwe_classification表应用断言。
        assert df_cwes.cwe_id.is_unique, "Primary keys are not unique in cwe records!"
        assert df_cwes_class.set_index(['cve_id', 'cwe_id']).index.is_unique, \
            'Primary keys are not unique in cwe_classification records!'
        assert set(list(df_cwes_class.cwe_id)).issubset(set(list(df_cwes.cwe_id))), \
            'Not all foreign keys for the cwe_classification records are present in the cwe table!'

        # 写入数据库: cwe表,cwe_classification表
        df_cwes = df_cwes[cwe_columns].reset_index()  # to maintain the order of the columns
        df_cwes.to_sql(name="cwe", con=db.conn, if_exists='replace', index=False)
        df_cwes_class.to_sql(name='cwe_classification', con=db.conn, if_exists='replace', index=False)
        cf.logger.info('Added cwe and cwe_classification tables')

        # --------------------------------------------------------------------------------------------------------
