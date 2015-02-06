/// <summary>
///    Copyright 2015 Matthew Sanaker, matthew@sanaker.com, @msanaker on GitHub
///    
///    This file is part of userContext.
///
///    userContext is free software: you can redistribute it and/or modify
///    it under the terms of the GNU General Public License as published by
///    the Free Software Foundation, either version 3 of the License, or
///    (at your option) any later version.
///
///    userContext is distributed in the hope that it will be useful,
///    but WITHOUT ANY WARRANTY; without even the implied warranty of
///    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
///    GNU General Public License for more details.
///
///    You should have received a copy of the GNU General Public License
///    along with userContext.  If not, see <http://www.gnu.org/licenses/>.
/// </summary>

using System;
using System.Security.Authentication;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

namespace userManagement
{
    /// <summary>
    /// userContext allows for AD authentication and gives the abiltiy to present an Active Directory user to an applicaiton including group memebership
    /// </summary>
    class userContext
    {
        public bool loggedOn { get; private set; }
        public UserPrincipal SAMAccount { get; private set; }
        public PrincipalSearchResult<Principal> currentUserAuthorizationGroups { get; private set; }

        /// <summary>
        /// Authenticates with Active Directory and returns a populated userContext object if authentication is successful
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static userContext authenticateUser(string userName, string password)
        {
            try
            {
                userContext uContext = new userContext();
                bool authenticated = false;
                PrincipalContext domainContext = new PrincipalContext(ContextType.Domain, Properties.Settings.Default.domain, Properties.Settings.Default.domainLDAPbase);
                authenticated = domainContext.ValidateCredentials(userName, password, ContextOptions.Negotiate);
                if (authenticated)
                {
                    uContext.loggedOn = true;
                    uContext.SAMAccount = userContext.getUserAccount(userName);
                    uContext.currentUserAuthorizationGroups = userContext.getGroups(userName);
                }
                else
                {
                    uContext.loggedOn = false;
                }
                return uContext;
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException ex)
            {
                throw ex;
            } 
        }

        /// <summary>
        /// Get an Active Directory User account by user name
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public static UserPrincipal getUserAccount(string userName)
        {
            try
            {
                PrincipalContext domainContext = new PrincipalContext(ContextType.Domain, Properties.Settings.Default.domain, Properties.Settings.Default.domainLDAPbase);
                UserPrincipal thisUser = UserPrincipal.FindByIdentity(domainContext, userName);
                return thisUser;
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException ex)
            {
                throw ex;
            } 
        }

        /// <summary>
        /// Get an Active Directory User account by GUID
        /// </summary>
        /// <param name="userGuid"></param>
        /// <returns></returns>
        public static UserPrincipal getUserAccount(Guid userGuid)
        {
            try
            {
                PrincipalContext domainContext = new PrincipalContext(ContextType.Domain, Properties.Settings.Default.domain, Properties.Settings.Default.domainLDAPbase);
                UserPrincipal thisUser = UserPrincipal.FindByIdentity(domainContext, IdentityType.Guid, userGuid.ToString());
                return thisUser;
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException ex)
            {
                throw ex;
            } 
        }

        /// <summary>
        /// Get Active Directory group membership for a user account
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public static PrincipalSearchResult<Principal> getGroups(string userName)
        {
            try
            {
            PrincipalContext domainContext = new PrincipalContext(ContextType.Domain, Properties.Settings.Default.domain, Properties.Settings.Default.domainLDAPbase);
            UserPrincipal thisUser = UserPrincipal.FindByIdentity(domainContext, userName);
            PrincipalSearchResult<Principal> groups = thisUser.GetGroups();
            return groups;
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException ex)
            {
                throw ex;
            } 
        }
    }
}
