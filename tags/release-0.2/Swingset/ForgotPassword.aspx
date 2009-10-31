<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="ForgotPassword.aspx.cs" Inherits="Owasp.Esapi.Swingset.ForgotPassword" MasterPageFile="~/Esapi.Master"%>
<asp:Content ID="ForgotPassswordContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server">
    Please enter your user name:
    <div><asp:TextBox ID="txtUserName" runat="server" /></div>
    <div><asp:Button ID="btnSubmit" runat="server" Text="Submit" onclick="btnSubmit_Click" /></div>    
</asp:Content>