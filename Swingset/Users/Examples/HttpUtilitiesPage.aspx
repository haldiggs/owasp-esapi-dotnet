<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="HttpUtilitiesPage.aspx.cs" Inherits="Owasp.Esapi.Swingset.Users.Examples.HttpUtilitiesPage" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="HttpUtiltiesContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server">
    <p>Current Session ID:<asp:Label ID="lblSessionId" runat="server"></asp:Label></p>
<asp:Button ID="btnChangeSessionId" runat="server" Text="Change Session ID" 
        onclick="btnChangeSessionId_Click" />
        
<p>CSRF-Protected Link</p>
<asp:HyperLink ID="hlCsrf" runat="server"></asp:HyperLink>
<asp:Label ID="lblCsrf"  runat="server" Text=""></asp:Label>
</asp:Content>