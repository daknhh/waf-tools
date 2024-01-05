import boto3
from tabulate import tabulate
from tqdm import tqdm
import datetime
import argparse
from cfonts import render, say

waf_client = boto3.client('wafv2')

def get_all_ipsets(scope):
  ipsets = []
  # Call ListIPSets API
  response = waf_client.list_ip_sets(Scope=scope)  
  for ipset in response['IPSets']:
    ipsets.append(ipset)
  # Check for pagination
  if 'NextMarker' in response:
    # Make additional call(s) to get all IP sets
    pass 
  return ipsets

def get_all_regexpatternsets(scope):
  regexpatternsets = []
  # Call ListIPSets API
  response = waf_client.list_regex_pattern_sets(Scope=scope)  
  for regexpatternset in response['RegexPatternSets']:
    regexpatternsets.append(regexpatternset)
  # Check for pagination
  if 'NextMarker' in response:
    # Make additional call(s) to get all IP sets
    pass 
  return regexpatternsets
  
def checkallipsets(ipsets, scope, webacls, rulegroups):
  ipsetusage = []
  # Loop through each IP set
  for ipset in tqdm(ipsets, desc="Progress"):
    # Check usage of this IP set
    ipsetusage= check_ipset_usage(ipset, ipsetusage, scope, webacls, rulegroups)
  return ipsetusage

def checkallregexpatternsets(regexpatternsets, scope, webacls, rulegroups):
  regexsetusage = []
  # Loop through each IP set
  for regexpatternset in tqdm(regexpatternsets, desc="Progress"):
    # Check usage of this IP set
    regexsetusage = check_regexset_usage(regexpatternset, regexsetusage, scope, webacls, rulegroups)
  return regexsetusage

def get_all_webacls(scope):
  # Get the list of all WebACLs
  webacl_response = waf_client.list_web_acls(Scope=scope)
  webacls = [webacl for webacl in webacl_response['WebACLs']]
  return webacls

def get_all_rulegroups(scope):
    # Get the list of all RuleGroups 
    rulegroup_response = waf_client.list_rule_groups(Scope=scope)
    rulegroups = [rulegroup for rulegroup in rulegroup_response['RuleGroups']]
    return rulegroups

def check_ipset_usage(ipset, ipsetusage, scope, webacls, rulegroups):
  WebACL = []
  Rulegroup = []
  FoundRulegroup = False
  FoundWebACL = False
  # Check the IP set usage in each WebACL
  for webacl in webacls:
    if check_webacl(waf_client, ipset['ARN'], webacl, scope, "IPSetReferenceStatement"):
      WebACL.append(webacl['Name'])
      FoundWebACL = True

  # Check the IP set usage in each RuleGroup  
  for rulegroup in rulegroups:
    if check_rulegroup(waf_client, ipset['ARN'], rulegroup, scope, "IPSetReferenceStatement"):
      FoundRulegroup = True
      Rulegroup.append(rulegroup['Name'])

  if(FoundRulegroup):
    Rulegroup = '\n'.join(Rulegroup)
  else:
    Rulegroup = "❌"
  if(FoundWebACL):
    WebACL = '\n'.join(WebACL)
  else:
    WebACL = "❌"

  ipsetusage.extend([[ipset['Name'], WebACL.strip(), Rulegroup.strip()]])
  return ipsetusage
def check_regexset_usage(regexpatternset, regexsetusage, scope, webacls, rulegroups):
  WebACL = []
  Rulegroup = []
  FoundRulegroup = False
  FoundWebACL = False

  # Check the RegexPatternSet usage in each WebACL
  for webacl in webacls:
    if check_webacl(waf_client, regexpatternset['ARN'], webacl, scope, "RegexPatternSetReferenceStatement"):
      WebACL.append(webacl['Name'])
      FoundWebACL = True
  # Check the RegexPatternSet usage in each RuleGroup
  for rulegroup in rulegroups:
    if check_rulegroup(waf_client, regexpatternset['ARN'], rulegroup, scope, "RegexPatternSetReferenceStatement"):
      FoundRulegroup = True
      Rulegroup.append(rulegroup['Name'])

  if(FoundRulegroup):
    Rulegroup = '\n'.join(Rulegroup)
  else:
    Rulegroup = "❌"
  if(FoundWebACL):
    WebACL = '\n'.join(WebACL)
  else:
    WebACL = "❌"

  regexsetusage.extend([[regexpatternset['Name'], WebACL.strip(), Rulegroup.strip()]])
  return regexsetusage
def check_webacl(waf_client, statement_set_arn, webacl, scope, statement):
  # Check if the IP set is referenced in the WebACL
  rules = waf_client.get_web_acl(Id=webacl['Id'], Name=webacl['Name'], Scope=scope)

  if('PostProcessFirewallManagerRuleGroups' in rules['WebACL']):
    for rule in rules['WebACL']['PostProcessFirewallManagerRuleGroups']:
        if statement in rule:
            if rule[statement]['ARN'] == statement_set_arn:
                return True
        elif 'AndStatement' in rule:
          if(check_statements(rule['AndStatement'], statement_set_arn, statement)):
                return True
        elif 'OrStatement' in rule:
          if(check_statements(rule['OrStatement'], statement_set_arn, statement)):
                return True
        elif 'NotStatement' in rule:
          if(check_statements(rule['NotStatement'], statement_set_arn, statement)):
                return True
  if('PreProcessFirewallManagerRuleGroups' in rules['WebACL']):
    for rule in rules['WebACL']['PreProcessFirewallManagerRuleGroups']:
        if statement in rule:
            if rule[statement]['ARN'] == statement_set_arn:
                return True
        elif 'AndStatement' in rule:
          if(check_statements(rule['AndStatement'], statement_set_arn, statement)):
                return True
        elif 'OrStatement' in rule:
          if(check_statements(rule['OrStatement'], statement_set_arn, statement)):
                return True
        elif 'NotStatement' in rule:
          if(check_statements(rule['NotStatement'], statement_set_arn, statement)):
                return True
  if('Rules' in rules['WebACL']):
    for rule in rules['WebACL']['Rules']:
        if statement in rule:
            if rule[statement]['ARN'] == statement_set_arn:
                return True
        elif 'AndStatement' in rule:
          if(check_statements(rule['AndStatement'], statement_set_arn, statement)):
                return True
        elif 'OrStatement' in rule:
          if(check_statements(rule['OrStatement'], statement_set_arn, statement)):
                return True
        elif 'NotStatement' in rule:
          if(check_statements(rule['NotStatement'], statement_set_arn, statement)):
                return True
  return False

def check_rulegroup(waf_client, statement_set_arn, rulegroup, scope, statement):

  # Get the RuleGroup details
  rulegroup = waf_client.get_rule_group(Scope=scope, Name=rulegroup['Name'], Id=rulegroup['Id'])
  for rule in rulegroup['RuleGroup']['Rules']:
    if statement in rule['Statement']:
        if rule['Statement'][statement]['ARN'] == statement_set_arn:
            return True
    elif 'AndStatement' in rule['Statement']:
      if(check_statements(rule['Statement']['AndStatement'], statement_set_arn, statement)):
            return True
    elif 'OrStatement' in rule['Statement']:
      if(check_statements(rule['Statement']['OrStatement'], statement_set_arn, statement)):
            return True
    elif 'NotStatement' in rule['Statement']:
      if(check_statements(rule['Statement']['NotStatement'], statement_set_arn, statement)):
            return True
  return False

def check_statements(rule, statement_set_arn, statement):
  if 'Statements' in rule:
    for rulestatement in rule['Statements']:
      # Check if the IP set is referenced in the WebACL
      if statement in rulestatement:
        if rulestatement[statement]['ARN'] == statement_set_arn:
            return True



parser = argparse.ArgumentParser()
parser.add_argument('--s', help='--s define Scope REGIONAL or CLOUDFRONT', default="REGIONAL")
parser.add_argument('--u', help='--u IPSet or RegexPatternSet', required=True)
args = parser.parse_args()
session = boto3.session.Session()
region = session.region_name
account = session.client('sts').get_caller_identity().get('Account')

title = render('GuardScope Analyzer', colors=['red', 'yellow'], align='center', font='pallet')
print(title)
subtitle = render('🔍 Checking IPSet or RegexPatternSet usage in your AWS Account\n 🔗 - linkedin.com/in/daknhh 🔀 daknhh\n\n ', colors=['white'], align='center', font='console')
print(subtitle)
print(f"""⚙️  SETTINGS: \n   Boto3: {boto3.__version__} \n   Scope: {args.s} \n   Usage: {args.u} \n   Region: {region} \n   Account: {account} \n""")

if(args.u == "IPSets"):
    ipsets = get_all_ipsets(args.s)
    webacls = get_all_webacls(args.s)
    rulegroups = get_all_rulegroups(args.s)
    headers=["IpSet", "WebACL", "RuleGroup(s)"]
    ipsetusage = checkallipsets(ipsets, args.s, webacls, rulegroups)
    print("\n\n", tabulate(ipsetusage, headers))
    generationTime = datetime.datetime.now()
    print(f"""\n 🧮 Number of \n     WebACLs: {len(webacls)} \n      RuleGroups: {len(rulegroups)} \n     IPSets: {len(ipsets)} \n\n ℹ️  Legend: ❌ = Not Used \n\n 🗓: {generationTime} +0000 UTC""")
    exit()
if(args.u == "RegexPatternSets"):
    regexpatternsets = get_all_regexpatternsets(args.s)
    webacls = get_all_webacls(args.s)
    rulegroups = get_all_rulegroups(args.s)
    headers=["RegexPatternSets", "WebACL", "RuleGroup(s)"]
    regexsetusage = checkallregexpatternsets(regexpatternsets, args.s, webacls, rulegroups)
    print("\n\n", tabulate(regexsetusage, headers))
    generationTime = datetime.datetime.now()
    print(f"""\n 🧮 Number of \n     WebACLs: {len(webacls)} \n     RuleGroups: {len(rulegroups)} \n     RegexPatternSets: {len(regexpatternsets)} \n\n ℹ️  Legend: ❌ = Not Used \n\n 🗓: {generationTime} +0000 UTC""")
    exit()

