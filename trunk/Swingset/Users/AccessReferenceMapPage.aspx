<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="AccessReferenceMapPage.aspx.cs" Inherits="Owasp.Esapi.Swingset.Users.AccessReferenceMap" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="AccessReferenceMapContent" ContentPlaceHolderID="EsapiContentPlaceHolder" runat="server">
    <asp:ObjectDataSource ID="odsAccounts" runat="server" 
        SelectMethod="GetIndirectAccounts"
        TypeName="Accounts">
    </asp:ObjectDataSource>
    <asp:Repeater ID="accountsRepeater" runat="server" DataSourceID="odsAccounts">
        
    </asp:Repeater>
    
</asp:Content>