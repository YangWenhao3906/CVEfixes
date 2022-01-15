import pandas as pd
import requests
import time
from github import Github
from github.GithubException import BadCredentialsException

import configuration as cf
import database as db
from collect_commits import extract_commits, extract_project_links
import cve_importer
from utils import prune_tables


repo_columns = [
    'repo_url',
    'repo_name',
    'description',
    'date_created',
    'date_last_push',
    'homepage',
    'repo_language',
    'owner',
    'forks_count',
    'stars_count'
]


def filter_urls(urls):
    """
    returns the non-existing urls
    @param urls 对urls进行requests, 若状态码大于等于400, 认定url不存在
    @return list 经测试已经不存在的url
    """
    sleeptime = 0
    non_exist_urls = []
    for url in urls:
        code = requests.head(url).status_code

        '''
        http状态码429 Too Many Requests （RFC 6585）
        用户在给定的时间内发送了太多的请求。旨在用于网络限速。
        => 增加sleep时间
        '''
        while code == 429:
            sleeptime += 10
            time.sleep(sleeptime)
            code = requests.head(url).status_code

        if code >= 400:
            non_exist_urls.append(url + ',' + str(code))

        sleeptime = 0

    return non_exist_urls



def convert_runtime(start_time, end_time):
    """
    converts runtime of the slice of code more readable format
    """
    runtime = end_time - start_time
    hours = runtime/3600
    minutes = (runtime % 3600)/60
    seconds = (runtime % 3600) % 60
    return hours, minutes, seconds



def get_ref_links():
    """
    retrieves reference links from CVE records to populate 'fixes' table
    从CVE记录中检索引用链接来构造'fixes'表
    @return fixes表转成Pandas的DataFrame
    """
    # 若db中已存在fixes表 => fixes表中的所有内容保存在df_fixes中
    if db.table_exists('fixes'):
        if cf.SAMPLE_LIMIT > 0:
            df_fixes = pd.read_sql("SELECT * FROM fixes LIMIT " + str(cf.SAMPLE_LIMIT), con=db.conn)
            df_fixes.to_sql(name='fixes', con=db.conn, if_exists='replace', index=False)
        else:
            df_fixes = pd.read_sql("SELECT * FROM fixes", con=db.conn)
            
    # 若db中不存在fixes表
    else:
        # [step1] 将cve表中所有内容保存在df_master中
        df_master = pd.read_sql("SELECT * FROM cve", con=db.conn)
        
        # [step2] 将ref在GitHub等代码托管网站中的放入df_fixes,并通过http访问测试过滤不存在的url
        df_fixes = extract_project_links(df_master)

        cf.logger.info('Checking if references still exist...')
        unique_urls = set(list(df_fixes.repo_url))

        # 通过http访问测试url
        unfetched_urls = []
        unfetched_urls = filter_urls(unique_urls)

        # logger输出不存在的url
        if len(unfetched_urls) > 0:
            cf.logger.debug('The following URLs are not accessible:')
            cf.logger.debug(unfetched_urls)

        # filtering out non-existing repo_urls 过滤不存在的url
        df_fixes = df_fixes[~df_fixes['repo_url'].isin(unfetched_urls)]

        if cf.SAMPLE_LIMIT > 0:
            # filtering out some of the major projects that would take a long time for a simplified example database.
            df_fixes = df_fixes[~df_fixes.repo_url.isin(['https://github.com/torvalds/linux',
                                                         'https://github.com/ImageMagick/ImageMagick',
                                                         'https://github.com/the-tcpdump-group/tcpdump',
                                                         'https://github.com/phpmyadmin/phpmyadmin',
                                                         'https://github.com/FFmpeg/FFmpeg'])]
            df_fixes = df_fixes.head(int(cf.SAMPLE_LIMIT))
            
        # 写入数据库fixes table 
        df_fixes.to_sql(name='fixes', con=db.conn, if_exists='replace', index=False)

    return df_fixes



def get_github_meta(repo_url, username, token):
    """
    returns github meta-information of the repo_url
    """
    owner, project = repo_url.split('/')[-2], repo_url.split('/')[-1]
    meta_row ={}

    if username == 'None':
        git_link = Github()
    else:
        git_link = Github(login_or_token=token, user_agent=username)

    try:
        git_user = git_link.get_user(owner)
        repo = git_user.get_repo(project)
        meta_row = {'repo_url': repo_url,
                    'repo_name': repo.full_name,
                    'description': repo.description,
                    'date_created': repo.created_at,
                    'date_last_push': repo.pushed_at,
                    'homepage': repo.homepage,
                    'repo_language': repo.language,
                    'forks_count': repo.forks,
                    'stars_count': repo.stargazers_count,
                    'owner': owner}
    except BadCredentialsException as e:
        cf.logger.warning(f'Credential problem while accessing GitHub repository {repo_url}\n', getattr(e, 'message', repr(e)))
        pass  # or exit(1)
    except Exception as e:
        cf.logger.warning(f'Other issues while getting meta-data for GitHub repository {repo_url}\n', e)
        pass  # or exit(1)
    return meta_row



def save_repo_meta(repo_url):
    """
    populate repository meta-information in repository table.
    """
    if 'github.' in repo_url:
        try:
            meta_dict = get_github_meta(repo_url, cf.USER, cf.TOKEN)
            df_meta = pd.DataFrame([meta_dict], columns=repo_columns)

            if db.table_exists('repository'):
                # ignore when the meta-information of the given repo is already saved.
                if db.fetchone_query('repository', 'repo_url', repo_url) is False:
                    df_meta.to_sql(name='repository', con=db.conn, if_exists="append", index=False)
            else:
                df_meta.to_sql(name='repository', con=db.conn, if_exists="replace", index=False)
        except Exception as e:
            cf.logger.warning('Problem while fetching repository meta-information\n', e)



def store_tables(df_fixes):
    """
    Fetch the commits and save the extracted data into commit-, file- and method level tables.
    获取提交并将提取的数据保存到提交、文件和方法级表中。
    """

    # 若已存在commits表,过滤fixes表中已经fetch的commits
    if db.table_exists('commits'):
        # 从fixes表和commits表中找哈希值相同的项
        # ? 疑问: 为什么, 应该是不需要再检索添加了
        query_done_hashes = "SELECT x.hash FROM fixes x, commits c WHERE x.hash = c.hash;"
        hash_done = list((pd.read_sql(query_done_hashes, con=db.conn))['hash'])
        df_fixes = df_fixes[~df_fixes.hash.isin(hash_done)]  # filtering out already fetched commits

    '''pandas DataFrame.unique: 返回一列的所有唯一的元素'''
    repo_urls = df_fixes.repo_url.unique()
    # repo_urls = ['https://github.com/khaledhosny/ots']  # just to check for debugging
    # hashes = ['003c62d28ae438aa8943cb31535563397f838a2c', 'fd']
    # ? pcount: 用于对url计数
    pcount = 0

    # loop: 遍历所有URL,找hashes即找commits
    # 因为url仅仅是ref,一个cve对其的commits可能多个,应该是一个多对多/一对多的关系
    # ? 但是一个url就是一个commits,就只对应一个hash
    for repo_url in repo_urls:
        pcount += 1
        try:
            # 获取repo_url对应的df(可能有多行,不止一行)
            df_single_repo = df_fixes[df_fixes.repo_url == repo_url]
            # 获取df中URL对应的所有hashes
            hashes = list(df_single_repo.hash.unique())
            cf.logger.info('-' * 70)
            cf.logger.info('Retrieving fixes for repo', pcount, 'of', len(repo_urls),
                  '-',  repo_url.rsplit("/")[-1])

            # extract_commits method returns data at different granularity levels
            # extract_commits方法返回不同粒度级别的数据
            df_commit, df_file, df_method = extract_commits(repo_url, hashes)

            if df_commit is not None:
                with db.conn:
                    # ----------------appending each project data to the tables-------------------------------
                    df_commit = df_commit.applymap(str) # 元素全部转成str
                    df_commit.to_sql(name="commits", con=db.conn, if_exists="append", index=False) # 加入数据库commits表
                    cf.logger.debug('#Commits :', len(df_commit))

                    if df_file is not None:
                        df_file = df_file.applymap(str)
                        df_file.to_sql(name="file_change", con=db.conn, if_exists="append", index=False)
                        cf.logger.debug('#Files   :', len(df_file))

                    if df_method is not None:
                        df_method = df_method.applymap(str)
                        df_method.to_sql(name="method_change", con=db.conn, if_exists="append", index=False)
                        cf.logger.debug('#Methods :', len(df_method))

                    save_repo_meta(repo_url)
            else:
                cf.logger.warning(f'Could not retrieve commit information from: {repo_url}\n')

        except Exception as e:
            cf.logger.warning(f'Problem occurred while retrieving the project: {repo_url}\n', e)
            pass  # skip fetching repository if is not available.


    cf.logger.debug('-' * 70)
    if db.table_exists('commits'):
        commit_count = str(pd.read_sql("SELECT count(*) FROM commits", con=db.conn).iloc[0].iloc[0])
        cf.logger.debug(f'Number of commits retrieved from all the repos: {commit_count}')
    else:
        cf.logger.warning('The commits table does not exist')


    if db.table_exists('file_change'):
        file_count = str(pd.read_sql("SELECT count(*) from file_change;", con=db.conn).iloc[0].iloc[0])
        cf.logger.debug(f'Number of files changed by all the commits: {file_count}')
    else:
        cf.logger.warning('The file_change table does not exist')

    if db.table_exists('method_change'):
        method_count = str(pd.read_sql("SELECT count(*) from method_change;", con=db.conn).iloc[0].iloc[0])
        cf.logger.debug(f'Number of total methods fetched by all the commits: {method_count}')

        vul_method_count = pd.read_sql('SELECT count(*) from method_change WHERE before_change="True";', con=db.conn).iloc[0].iloc[0]
        cf.logger.debug(f"Number of vulnerable methods fetched by all the commits: {vul_method_count}")
    else:
        cf.logger.warning('The method_change table does not exist')

    cf.logger.info('-' * 70)


# ---------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    start_time = time.perf_counter()
    # Step (1) save CVEs(cve) and cwe tables 
    # 保存cve,cwe,cwe_classification 3张表
    cve_importer.import_cves()
    # Step (2) save commit-, file-, and method- level data tables to the database
    # 将提交级、文件级和方法级数据表保存到数据库
    store_tables(get_ref_links())
    # Step (3) pruning the database tables
    # 修剪数据库表:过滤掉未链接的数据
    if db.table_exists('method_change'):
        # 从表中过滤掉未链接的数据
        prune_tables(cf.DATABASE)
    else:
        cf.logger.warning('Data pruning is not possible because there is not information in method_change table')

    cf.logger.info('The database is up-to-date.')
    cf.logger.info('-' * 70)
    end_time = time.perf_counter()
    hours, minutes, seconds = convert_runtime(start_time, end_time)
    cf.logger.info(f'Time elapsed to pull the data {hours:02.0f}:{minutes:02.0f}:{seconds:02.0f} (hh:mm:ss).')
# ---------------------------------------------------------------------------------------------------------------------