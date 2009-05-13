<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="AccessReferenceMap.aspx.cs" Inherits="Owasp.Esapi.Swingset.Users.AccessReferenceMapPage" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="AccessReferenceMapContent" ContentPlaceHolderID="EsapiContentPlaceHolder" runat="server">
    <asp:ObjectDataSource ID="odsAccounts" runat="server" 
        SelectMethod="GetAccountReferences" TypeName="Owasp.Esapi.Swingset.AccountMapper">
    </asp:ObjectDataSource>
    <asp:Repeater ID="accountsRepeater" runat="server" DataSourceID="odsAccounts">
        <ItemTemplate>
            <asp:HyperLink NavigateUrl='<%# String.Format("Account.aspx?id={0}", DataBinder.Eval(Container.DataItem, "reference")) %>' 
                           Text='<%# DataBinder.Eval(Container.DataItem, "name") %>' 
                           runat="server" ID="hlAccount" /> <br>
        </ItemTemplate>
    </asp:Repeater>    
</asp:Content>