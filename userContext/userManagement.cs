/// <summary>
///    Copyright 2015 Matthew Sanaker, matthew@sanaker.com, @msanaker on GitHub
///    
///    This file is part of userManagement.
///
///    userManagement is free software: you can redistribute it and/or modify
///    it under the terms of the GNU General Public License as published by
///    the Free Software Foundation, either version 3 of the License, or
///    (at your option) any later version.
///
///    userManagement is distributed in the hope that it will be useful,
///    but WITHOUT ANY WARRANTY; without even the implied warranty of
///    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
///    GNU General Public License for more details.
///
///    You should have received a copy of the GNU General Public License
///    along with userManagement.  If not, see <http://www.gnu.org/licenses/>.
/// </summary>

using System;
using System.Security.Authentication;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Globalization;

namespace userManagement
{
    /// <summary>
    /// accountManagement allows for Active Directory account creation and editing following particular user account naming conventions
    /// User accounts are created using a firstName.lastName convention
    /// </summary>
    class ADaccountManagement
    {
        /// <summary>
        /// Creates an Active Directory user using a firstName.lastName convention in the default Users container for the domain 
        /// </summary>
        /// <param name="firstName"></param>
        /// <param name="lastName"></param>
        /// <returns>UserPrincipal</returns>
        public static UserPrincipal createUser(string firstName, string lastName, string password)
        {
            try
            {
                PrincipalContext domainContext = new PrincipalContext(ContextType.Domain, Properties.Settings.Default.domain, Properties.Settings.Default.domainLDAPbase);
                UserPrincipal newUser = new UserPrincipal(domainContext);
                newUser.GivenName = new CultureInfo("en-US").TextInfo.ToTitleCase(firstName);
                newUser.Surname = new CultureInfo("en-US").TextInfo.ToTitleCase(lastName);
                string display = new CultureInfo("en-US").TextInfo.ToTitleCase(firstName + " " + lastName);
                newUser.Name = display;
                newUser.DisplayName = display;
                newUser.SamAccountName = firstName.ToLowerInvariant() + "." + lastName.ToLowerInvariant();
                newUser.Save();
                newUser.SetPassword(password);
                newUser.ExpirePasswordNow();
                newUser.Enabled = true;
                return newUser;
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException ex)
            {
                throw ex;
            } 
        }

        /// <summary>
        /// Creates an Active Directory user using a firstName.lastName convention in the specificied OU in the domain
        /// </summary>
        /// <param name="firstName"></param>
        /// <param name="lastName"></param>
        /// <param name="OU"></param>
        /// <returns>UserPrincipal</returns>
        public static UserPrincipal createUser(string firstName, string lastName, string password, string OU)
        {
            try
            {
                string LDAPpath = "OU=" + OU + "," + Properties.Settings.Default.domainLDAPbase;
                PrincipalContext domainContext = new PrincipalContext(ContextType.Domain, Properties.Settings.Default.domain, LDAPpath);
                UserPrincipal newUser = new UserPrincipal(domainContext);
                newUser.GivenName = new CultureInfo("en-US").TextInfo.ToTitleCase(firstName);
                newUser.Surname = new CultureInfo("en-US").TextInfo.ToTitleCase(lastName);
                string display = new CultureInfo("en-US").TextInfo.ToTitleCase(firstName + " " + lastName);
                newUser.Name = display;
                newUser.DisplayName = display;
                newUser.SamAccountName = firstName.ToLowerInvariant() + "." + lastName.ToLowerInvariant();
                newUser.Save();
                newUser.SetPassword(password);
                newUser.ExpirePasswordNow();
                newUser.Enabled = true;
                return newUser;
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Creates an Active Directory user using a firstName.lastName convention in the specificied OU in the domain by making a copy of an existing user
        /// </summary>
        /// <param name="firstName"></param>
        /// <param name="lastName"></param>
        /// <param name="password"></param>
        /// <param name="OU"></param>
        /// <param name="userToCopy"></param>
        /// <returns></returns>
        public static UserPrincipal createUser(string firstName, string lastName, string password, string OU, UserPrincipal userToCopy)
        {
            try
            {
                string LDAPpath = "OU=" + OU + "," + Properties.Settings.Default.domainLDAPbase;
                PrincipalContext domainContext = new PrincipalContext(ContextType.Domain, Properties.Settings.Default.domain, LDAPpath);
                UserPrincipal newUser = new UserPrincipal(domainContext);
                newUser.GivenName = new CultureInfo("en-US").TextInfo.ToTitleCase(firstName);
                newUser.Surname = new CultureInfo("en-US").TextInfo.ToTitleCase(lastName);
                string display = new CultureInfo("en-US").TextInfo.ToTitleCase(firstName + " " + lastName);
                newUser.Name = display;
                newUser.DisplayName = display;
                newUser.SamAccountName = firstName.ToLowerInvariant() + "." + lastName.ToLowerInvariant();
                string[] upnParts = userToCopy.UserPrincipalName.Split(new Char [] {'@'});
                newUser.UserPrincipalName = newUser.SamAccountName + "@" + upnParts[1];
                newUser.Save();
                newUser.SetPassword(password);
                newUser.ExpirePasswordNow();
                PrincipalSearchResult<Principal> groups = userContext.getGroups(userToCopy.SamAccountName);
                foreach (Principal g in groups)
                {
                    GroupPrincipal group = GroupPrincipal.FindByIdentity(domainContext, g.Name);
                    group.Members.Add(domainContext, IdentityType.UserPrincipalName, newUser.SamAccountName);
                    group.Save();
                }
                string company = getProperty(userToCopy, "Company");
                if (!(string.IsNullOrEmpty(company)))
                {
                    setProperty(newUser, "Company", company);
                }
                string dept = getProperty(userToCopy, "Department");

                newUser.Enabled = true;
                return newUser;
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException ex)
            {
                throw ex; 
            } 
        }

        /// <summary>
        /// Gets the value of a directory entry property for a given AD Principal object
        /// </summary>
        /// <param name="principal"></param>
        /// <param name="property"></param>
        /// <returns></returns>
        private static String getProperty(Principal principal, string property)
        {
            try
            {
            string value;
            DirectoryEntry dirEntry = principal.GetUnderlyingObject() as DirectoryEntry;
            if (dirEntry.Properties.Contains(property))
                value = dirEntry.Properties[property].Value.ToString();
            else
                value = String.Empty;
            return value;
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException ex)
            {
                throw ex;
            }

        }

        /// <summary>
        /// Sets the value of a directory entry property for a given AD Principal object
        /// </summary>
        /// <param name="principal"></param>
        /// <param name="property"></param>
        /// <param name="value"></param>
        private static void setProperty(Principal principal, string property, string value)
        {
            try
            {
                DirectoryEntry dirEntry = principal.GetUnderlyingObject() as DirectoryEntry;
                if (dirEntry.Properties.Contains(property))
                {
                    dirEntry.Properties[property].Value = value;
                }
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException ex)
            {
                throw ex;
            }
        }
    
    }


}
