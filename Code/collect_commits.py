import ast
import os
import re
import uuid

import pandas as pd
import configuration as cf
from guesslang import Guess
from pydriller import Repository
from utils import log_commit_urls


os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

fixes_columns = [
    'cve_id',
    'hash',
    'repo_url',
]

commit_columns = [
    'hash',
    'repo_url',
    'author',
    'author_date',
    'author_timezone',
    'committer',
    'committer_date',
    'committer_timezone',
    'msg',
    'merge',
    'parents',
    'num_lines_added',
    'num_lines_deleted',
    'dmm_unit_complexity',
    'dmm_unit_interfacing',
    'dmm_unit_size'
]

file_columns = [
    'file_change_id',
    'hash',
    'filename',
    'old_path',
    'new_path',
    'change_type',
    'diff',
    'diff_parsed',
    'num_lines_added',
    'num_lines_deleted',
    'code_after',
    'code_before',
    'nloc',
    'complexity',
    'token_count',
    'programming_language'
]

method_columns = [
    'method_change_id',
    'file_change_id',
    'name',
    'signature',
    'parameters',
    'start_line',
    'end_line',
    'code',
    'nloc',
    'complexity',
    'token_count',
    'top_nesting_level',
    'before_change',
]


def extract_project_links(df_master):
    """
    extracts all the reference urls from CVE records that match to the repo commit urls
    从CVE记录中提取与repo提交url匹配的所有reference url
    @return df_fixes
    """
    # [step1] 创建df_fixes保存在内存中
    df_fixes = pd.DataFrame(columns=fixes_columns)
    
    # 代码托管网站的commit的正则表达式
    # ! 注意:提取的仅有含commit的url
    git_url = r'(((?P<repo>(https|http):\/\/(bitbucket|github|gitlab)\.(org|com)\/(?P<owner>[^\/]+)\/(?P<project>[^\/]*))\/(commit|commits)\/(?P<hash>\w+)#?)+)'
    cf.logger.info('-' * 70)
    cf.logger.info('Extracting all the reference urls from CVE...')
    
    # [step2] 将ref在GitHub等网站中的加入df_fixes
    for i in range(len(df_master)):
        '''pandas DataFrame.iloc: 通过行号取数据; 返回: DataFrame'''
        '''ast literal_eval: 类型转换, 此处将DataFrame转成list'''
        ref_list = ast.literal_eval(df_master['reference_json'].iloc[i])
        if len(ref_list) > 0:
            # 若ref在GitHub等网站中,加入df_fixes
            for ref in ref_list:
                url = dict(ref)['url']
                '''re.search: 返回第一个成功的匹配'''
                link = re.search(git_url, url)
                if link:
                    row = {
                        # 从url中提取hash和url
                        'cve_id': df_master['cve_id'][i],
                        'hash': link.group('hash'),
                        'repo_url': link.group('repo').replace(r'http:', r'https:')
                    }
                    df_fixes = df_fixes.append(pd.Series(row), ignore_index=True)

    # 删掉重复的项并reset_index
    df_fixes = df_fixes.drop_duplicates().reset_index(drop=True)
    # logger输出找到的ref在GitHub中的数目
    cf.logger.info('Number of collected references to vulnerability fixing commits:', len(df_fixes))
    return df_fixes


def guess_pl(code):
    """
    :returns guessed programming language of the code
    """
    if code:
        return Guess().language_name(code.strip())
    else:
        return 'unknown'


def clean_string(signature):
    return signature.strip().replace(' ','')


def get_method_code(source_code, start_line, end_line):
    try:
        if source_code is not None:
            code = ('\n'.join(source_code.split('\n')[int(start_line) - 1: int(end_line)]))
            return code
        else:
            return None
    except Exception as e:
        cf.logger.warning('Problem while getting method code from the file!', e)
        pass


def changed_methods_both(file):
    """
    Return the list of methods that were changed.
    :return: list of methods
    """
    new_methods = file.methods
    old_methods = file.methods_before
    added = file.diff_parsed["added"]
    deleted = file.diff_parsed["deleted"]

    methods_changed_new = {
        y
        for x in added
        for y in new_methods
        if y.start_line <= x[0] <= y.end_line
    }
    methods_changed_old = {
        y
        for x in deleted
        for y in old_methods
        if y.start_line <= x[0] <= y.end_line
    }
    return methods_changed_new, methods_changed_old


# --------------------------------------------------------------------------------------------------------
# extracting method_change data 提取method_change数据
def get_methods(file, file_change_id):
    """
    returns the list of methods in the file.
    把file中的method信息提取出来
    """
    file_methods = []
    try:
        if file.changed_methods:
            cf.logger.debug('-' * 70)
            cf.logger.debug('\nmethods_after: ')
            cf.logger.debug('- ' * 35)
            for m in file.methods:
                if m.name != '(anonymous)':
                    cf.logger.debug(m.long_name)

            cf.logger.debug('\nmethods_before: ')
            cf.logger.debug('- ' * 35)
            for mb in file.methods_before:
                if mb.name != '(anonymous)':
                    cf.logger.debug(mb.long_name)

            cf.logger.debug('\nchanged_methods: ')
            cf.logger.debug('- ' * 35)
            for mc in file.changed_methods:
                if mc.name != '(anonymous)':
                    cf.logger.debug(mc.long_name)
            cf.logger.debug('-' * 70)

            # for mb in file.methods_before:
            #     for mc in file.changed_methods:
            #         #if mc.name == mb.name and mc.name != '(anonymous)':
            #         if clean_string(mc.long_name) == clean_string(mb.long_name) and mc.name != '(anonymous)':

            if file.changed_methods:
                methods_after, methods_before = changed_methods_both(file) # modified methods in source_code_after/_before
                if methods_before:
                    for mb in methods_before:
                        # filtering out code not existing, and (anonymous)
                        # because lizard API classifies the code part not as a correct function.
                        # Since, we did some manual test, (anonymous) function are not function code.
                        # They are also not listed in the changed functions.
                        if file.source_code_before is not None and mb.name != '(anonymous)':
                            # method_before_code = ('\n'.join(file.source_code_before.split('\n')[int(mb.start_line) - 1: int(mb.end_line)]))
                            method_before_code = get_method_code(file.source_code_before, mb.start_line, mb.end_line)
                            method_before_row = {
                                'method_change_id': uuid.uuid4().fields[-1],
                                'file_change_id': file_change_id,
                                'name': mb.name,
                                'signature': mb.long_name,
                                'parameters': mb.parameters,
                                'start_line': mb.start_line,
                                'end_line': mb.end_line,
                                'code': method_before_code,
                                'nloc': mb.nloc,
                                'complexity': mb.complexity,
                                'token_count': mb.token_count,
                                'top_nesting_level': mb.top_nesting_level,
                                'before_change': 'True',
                            }
                            file_methods.append(method_before_row)

                if methods_after:
                    for mc in methods_after:
                        if file.source_code is not None and mc.name != '(anonymous)':
                            # changed_method_code = ('\n'.join(file.source_code.split('\n')[int(mc.start_line) - 1: int(mc.end_line)]))
                            changed_method_code = get_method_code(file.source_code, mc.start_line, mc.end_line)
                            changed_method_row = {
                                'method_change_id': uuid.uuid4().fields[-1],
                                'file_change_id': file_change_id,
                                'name': mc.name,
                                'signature': mc.long_name,
                                'parameters': mc.parameters,
                                'start_line': mc.start_line,
                                'end_line': mc.end_line,
                                'code': changed_method_code,
                                'nloc': mc.nloc,
                                'complexity': mc.complexity,
                                'token_count': mc.token_count,
                                'top_nesting_level': mc.top_nesting_level,
                                'before_change': 'False',
                            }
                            file_methods.append(changed_method_row)

        if file_methods:
            return file_methods
        else:
            return None

    except Exception as e:
        cf.logger.warning('Problem while fetching the methods!', e)
        pass


# ---------------------------------------------------------------------------------------------------------
# extracting file_change data of each commit 提取每个提交的file_change数据
def get_files(commit):
    """
    returns the list of files of the commit.
    把commit中的关于文件的信息提取出来
    """
    commit_files = []
    commit_methods = []
    try:
        cf.logger.info(f'Extracting files for {commit.hash}')
        if commit.modified_files:
            for file in commit.modified_files:
                cf.logger.debug(f'Processing file {file.filename} in {commit.hash}')
                # programming_language = (file.filename.rsplit(".')[-1] if '.' in file.filename else None)
                programming_language = guess_pl(file.source_code)  # guessing the programming language of fixed code
                file_change_id = uuid.uuid4().fields[-1]

                file_row = {
                    'file_change_id': file_change_id,       # filename: primary key
                    'hash': commit.hash,                    # hash: foreign key
                    'filename': file.filename,
                    'old_path': file.old_path,
                    'new_path': file.new_path,
                    'change_type': file.change_type,        # i.e. added, deleted, modified or renamed
                    'diff': file.diff,                      # diff of the file as git presents it (e.g. @@xx.. @@)
                    'diff_parsed': file.diff_parsed,        # diff parsed in a dict containing added and deleted lines lines
                    'num_lines_added': file.added_lines,        # number of lines added
                    'num_lines_deleted': file.deleted_lines,    # number of lines removed
                    'code_after': file.source_code,
                    'code_before': file.source_code_before,
                    'nloc': file.nloc,
                    'complexity': file.complexity,
                    'token_count': file.token_count,
                    'programming_language': programming_language,
                }
                file_methods = []
                commit_files.append(file_row)
                file_methods = get_methods(file, file_change_id)

                if file_methods is not None:
                    commit_methods.extend(file_methods)
        else:
            cf.logger.info('The list of modified_files is empty')

        return commit_files, commit_methods

    except Exception as e:
        cf.logger.warning('Problem while fetching the files!', e)
        pass


def extract_commits(repo_url, hashes):
    """
    This function extract git commit information of only the hashes list that were specified in the
    commit URL. All the commit_fields of the corresponding commit have been obtained.
    Every git commit hash can be associated with one or more modified/manipulated files.
    One vulnerability with same hash can be fixed in multiple files so we have created a dataset of modified files
    as 'df_file' of a project.
    :param repo_url: list of url links of all the projects.
    :param hashes: list of hashes of the commits to collect
    :return dataframes: at commit level and file level.
    
    这个函数只提取git提交信息的哈希列表中指定的
    提交URL。已获取对应提交的所有commit_fields。
    每个git提交哈希可以与一个或多个被修改/操作的文件相关联。
    一个具有相同哈希的漏洞可以在多个文件中修复，因此我们创建了一个修改文件的数据集
    作为项目的'df_file'。
    :param repo_url:所有项目的url链接列表。
    :param hashes:要收集的提交的哈希列表
    :返回数据帧:在提交级和文件级。
    """
    repo_commits = []
    repo_files = []
    repo_methods = []

    # ----------------------------------------------------------------------------------------------------------------
    # extracting commit-level data
    if 'github' in repo_url:
        repo_url = repo_url + '.git'

    cf.logger.debug(f'Extracting commits for {repo_url} with {cf.NUM_WORKERS} worker(s) looking for the following hashes:')
    log_commit_urls(repo_url, hashes)

    # ? giving first priority to 'single' parameter for single hash because 
    # it has been tested that 'single' gets commit information in some cases where 'only_commits' does not,
    # 给单哈希参数'single'优先级，因为已经通过测试知道:在某些情况下,'single'获得提交信息，而'only_commits'没有提交信息，
    # for example: https://github.com/hedgedoc/hedgedoc.git/35b0d39a12aa35f27fba8c1f50b1886706e7efef
    single_hash = None
    if len(hashes) == 1:
        single_hash = hashes[0]
        hashes = None

    # 定位仓库的提交,并在commit/file/method层面分别进行存储
    for commit in Repository(path_to_repo=repo_url,
                             only_commits=hashes,
                             single=single_hash,
                             num_workers=cf.NUM_WORKERS).traverse_commits():
        cf.logger.debug(f'Processing {commit.hash}')
        try:
            commit_row = {
                'hash': commit.hash,
                'repo_url': repo_url,
                'author': commit.author.name,
                'author_date': commit.author_date,
                'author_timezone': commit.author_timezone,
                'committer': commit.committer.name,
                'committer_date': commit.committer_date,
                'committer_timezone': commit.committer_timezone,
                'msg': commit.msg,
                'merge': commit.merge,
                'parents': commit.parents,
                'num_lines_added': commit.insertions,
                'num_lines_deleted': commit.deletions,
                'dmm_unit_complexity': commit.dmm_unit_complexity,
                'dmm_unit_interfacing': commit.dmm_unit_interfacing,
                'dmm_unit_size': commit.dmm_unit_size,
            }
            # 获取commit对应的file和method层面的改变
            commit_files, commit_methods = get_files(commit)

            repo_commits.append(commit_row)
            repo_files.extend(commit_files)
            repo_methods.extend(commit_methods)

        except Exception as e:
            cf.logger.warning('Problem while fetching the commits!', e)
            pass

    if repo_commits:
        df_repo_commits = pd.DataFrame.from_dict(repo_commits)
        df_repo_commits = df_repo_commits[commit_columns]  # ordering the columns
    else:
        df_repo_commits = None

    if repo_files:
        df_repo_files = pd.DataFrame.from_dict(repo_files)
        df_repo_files = df_repo_files[file_columns]  # ordering the columns
    else:
        df_repo_files = None

    if repo_methods:
        df_repo_methods = pd.DataFrame.from_dict(repo_methods)
        df_repo_methods = df_repo_methods[method_columns]  # ordering the
    else:
        df_repo_methods = None


    return df_repo_commits, df_repo_files, df_repo_methods