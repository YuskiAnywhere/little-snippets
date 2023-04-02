//from Novell.Directory.Ldap.NETStandard package
using Novell.Directory.Ldap;

namespace YuskiAnywhere
{
    public class LdapHelper
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="host">domain name or IP address are valid</param>
        /// <param name="port">standard ports are 389, 636 (ldaps) for local domain controller and 3268, 3269 (ldaps) for global catalog</param>
        /// <exception cref="ArgumentException"></exception>
        public LdapHelper(string host, int port)
        {
            if (String.IsNullOrWhiteSpace(host))
                throw new ArgumentException(nameof(host));
            if (port <= 0)
                throw new ArgumentException(nameof(port));

            _host = host;
            _port = port;
        }

        private readonly string _host;
        private readonly int _port;
         
        /// <summary>
        /// Returns the user if it exists and its password is correct; otherwise throws an exception
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="Exception"></exception>
        public LdapUser GetUser(string domain, string username, string password)
        {
            if (String.IsNullOrWhiteSpace(domain))
                throw new ArgumentException(nameof(domain));

            using (LdapConnection ldapConnection = new LdapConnection())
            {
                ldapConnection.Constraints.ReferralFollowing = true;
                ldapConnection.SearchConstraints.ReferralFollowing = true;
                try
                {
                    ldapConnection.Connect(_host, _port);
                }
                catch (Exception ex)
                {
                    throw new Exception($"Error connecting to {_host}:{_port}", ex);
                }
                if (!ldapConnection.Connected)
                    throw new Exception($"Error connecting to {_host}:{_port}");

                try
                {
                    ldapConnection.Bind(LdapConnection.LdapV3, $"{username}@{domain}", password);
                }
                catch (Exception ex)
                {
                    throw new Exception($"Wrong credentials for {domain}\\{username}", ex);
                }
                if (!ldapConnection.Bound)
                    throw new Exception($"Wrong credentials for {domain}\\{username}");

                var requestDN = $"{String.Join(",", domain.Split('.').Select(x => $"dc={x}"))}";
                var userRequestFilter = $"(&(objectClass=person)(objectCategory=user)(sAMAccountName={username}))";

                ILdapSearchResults userResponse;
                try
                {
                    //added "uid" and "samaccountname" just for debugging
                    userResponse = ldapConnection.Search(requestDN, LdapConnection.ScopeSub, userRequestFilter, new string[] { "uid", "mail", "memberof", "samaccountname", "company", "displayname" }, false);
                }
                catch (Exception ex)
                {
                    throw new Exception($"Error searching for {userRequestFilter}", ex);
                }

                LdapUser result = null;
                foreach (var item in userResponse)
                {
                    result = new LdapUser();
                    result.UserName = $"{domain}\\{username}";
                    foreach (string attributeKey in item.GetAttributeSet().Select(x => x.Key))
                    {
                        var values = item.GetAttribute(attributeKey).StringValueArray;

                        if (String.Equals(attributeKey, "company", StringComparison.OrdinalIgnoreCase))
                        {
                            var value = String.Join(";", values.Select(x => x.ToString()));
                            result.CompanyName = value;
                        }
                        else if (String.Equals(attributeKey, "mail", StringComparison.OrdinalIgnoreCase))
                        {
                            var value = String.Join(";", values.Select(x => x.ToString()));
                            result.EMail = value;
                        }
                        else if (String.Equals(attributeKey, "displayname", StringComparison.OrdinalIgnoreCase))
                        {
                            var value = String.Join(";", values.Select(x => x.ToString()));
                            result.DisplayName = value;
                        }
                        else if (String.Equals(attributeKey, "memberof", StringComparison.OrdinalIgnoreCase))
                        {
                            result.GroupNames.UnionWith(values.Select(x => GetName(x)));
                        }
                    }
                    break;
                }
                if (result == null)
                    throw new Exception($"Nothing found while searching for {userRequestFilter}");

                foreach (var groupName in result.GroupNames.ToArray())
                {
                    result.GroupNames.UnionWith(GetMemberOfRecursive(ldapConnection, requestDN, groupName));
                }
                return result;
            }
        }

        private IEnumerable<string> GetMemberOfRecursive(LdapConnection ldapConnection, string requestDN, string groupName)
        {
            var groupRequestFilter = $"(&(objectClass=group)(cn={EscapeFilterParam(groupName)}))";

            ILdapSearchResults groupResponse;
            try
            {
                //added "uid" and "displayname" just for debugging
                groupResponse = ldapConnection.Search(requestDN, LdapConnection.ScopeSub, groupRequestFilter, new string[] { "uid", "memberof", "displayname" }, false, new LdapSearchConstraints() { ReferralFollowing = true });
            }
            catch (Exception ex)
            {
                throw new Exception($"Error searching for {groupRequestFilter}", ex);
            }

            var result = new HashSet<string>();
            foreach (var item in groupResponse)
            {
                foreach (string attributeKey in item.GetAttributeSet().Select(x => x.Key))
                {
                    var values = item.GetAttribute(attributeKey).StringValueArray;

                    if (String.Equals(attributeKey, "memberof", StringComparison.OrdinalIgnoreCase))
                    {
                        result.UnionWith(values.Select(x => GetName(x)));
                    }
                }
            }
            foreach (var parentGroupName in result.ToArray())
            {
                result.UnionWith(GetMemberOfRecursive(ldapConnection, requestDN, parentGroupName));
            }
            return result;
        }

        private string EscapeFilterParam(string groupName)
        {
            //sure there are more
            return groupName.Replace("\\", "").Replace("(", "\\(").Replace(")", "\\)").Replace("&", "\\&").Replace("|", "\\|").Replace("=", "\\=");
        }

        private string GetName(string value)
        {
            value = value.Replace("\\,", "@#$");

            var prefix = "CN=";
            var prefixLength = prefix.Length;

            var indexOfCN = value.IndexOf(prefix);
            if (indexOfCN == -1)
                return null;

            var indexOfComma = value.IndexOf(",", indexOfCN);
            if (indexOfComma == -1)
            {
                indexOfComma = value.Length;
            }
            var result = value.Substring(indexOfCN + prefixLength, indexOfComma - indexOfCN - prefixLength);
            result = result.Replace("@#$", "\\,");
            return result;
        }
    }

    public class LdapUser
    {
        public string UserName { get; set; }
        public string CompanyName { get; set; }
        public string EMail { get; set; }
        public string DisplayName { get; set; }
        public HashSet<string> GroupNames { get; } = new HashSet<string>();
    }
}
