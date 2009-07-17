<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="ChangePassword.aspx.cs" Inherits="Owasp.Esapi.Swingset.Users.ChangePassword" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="ChangePasswordContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server">
        <asp:ChangePassword ID="EsapiChangePassword" runat="server"         
            ChangePasswordFailureText="The password must be greater than eight characters and include one upper-case letter, one lower-case letter, one number, and one special character."            
            OnChangedPassword="EsapiChangePassword_ChangedPassword" 
            OnChangePassworderror="EsapiChangePassword_ChangePasswordError" 
            ConfirmPasswordCompareErrorMessage="Password and password confirmation must match.">        
        </asp:ChangePassword>
</asp:Content>