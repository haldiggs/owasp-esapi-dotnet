<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Login.aspx.cs" Inherits="Owasp.Esapi.Swingset.Login" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="LoginContent" ContentPlaceHolderID="EsapiContentPlaceHolder" runat="server">
        <asp:Login ID="EsapiLogin" runat="server" 
                CreateUserText="Register" 
                CreateUserUrl="~/Register.aspx" 
                PasswordRecoveryText="Forgot Password?" 
                PasswordRecoveryUrl="~/ForgotPassword.aspx"
                DisplayRememberMe="false" 
                OnLoggedIn="EsapiLogin_LoggedIn" 
                OnLoginError="EsapiLogin_LoginError" 
                OnAuthenticate="EsapiLogin_Authenticate" >
        </asp:Login>    
</asp:Content>