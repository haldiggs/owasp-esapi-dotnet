<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="Owasp.Esapi.Swingset._Default" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="DefaultContent" ContentPlaceHolderID="EsapiContentPlaceHolder" runat="server">
    <asp:LoginName ID="EsapiLoginName" runat="server" />
    <asp:LoginStatus ID="EsapiLoginStatus" runat="server" 
        onloggingout="EsapiLoginStatus_LoggingOut" />
</asp:Content>