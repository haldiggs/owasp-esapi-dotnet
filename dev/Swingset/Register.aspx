<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Register.aspx.cs" Inherits="Owasp.Esapi.Swingset.Register" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="RegisterContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server"> 
        <asp:CreateUserWizard ID="EsapiCreateUserWizard" runat="server"             
            InvalidPasswordErrorMessage="The password must be greater than eight characters and include one upper-case letter, one lower-case letter, one number, and one special character."            
            LoginCreatedUser="false" 
            OnCreatedUser="EsapiCreateUserWizard_CreatedUser" 
            ConfirmPasswordCompareErrorMessage="Password and password confirmation must match.">
            <WizardSteps>
                <asp:CreateUserWizardStep ID="EsapiCreateUserWizardStep" runat="server">                    
                </asp:CreateUserWizardStep>
                <asp:CompleteWizardStep ID="EsapiCompleteWizardStep" runat="server">
                </asp:CompleteWizardStep>
            </WizardSteps>
        </asp:CreateUserWizard>
</asp:Content>