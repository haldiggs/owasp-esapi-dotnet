<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Message.aspx.cs" Inherits="Owasp.Esapi.Swingset.Message"  MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="MessageContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server"> 
    <asp:Label ID="lblMessage" runat="server"></asp:Label>
    <div>
        <asp:HyperLink ID="hlLogin" runat="server" NavigateUrl="~/Login.aspx">Login</asp:HyperLink>
    </div>
</asp:Content>
