<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Login.aspx.cs" Inherits="Owasp.Esapi.Swingset.Login"
	MasterPageFile="~/Esapi.Master" %>

<asp:Content ID="LoginContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server">
	<p>
		Testing admin account login:<br />
		<%= Owasp.Esapi.Swingset.Global.AdminUserName %><br />
		<%= Owasp.Esapi.Swingset.Global.passWord %>
	</p>
	<asp:Login ID="EsapiLogin" runat="server" CreateUserText="Register" CreateUserUrl="~/Register.aspx"
		PasswordRecoveryText="Forgot Password?" PasswordRecoveryUrl="~/ForgotPassword.aspx"
		DisplayRememberMe="false" OnLoggedIn="EsapiLogin_LoggedIn" OnLoginError="EsapiLogin_LoginError"
		OnAuthenticate="EsapiLogin_Authenticate" TitleText="" UserName="admin" UserNameLabelText="Username" PasswordLabelText="Password" CssClass="login">
	</asp:Login>
</asp:Content>
