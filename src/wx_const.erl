-module(wx_const).

-include_lib("wx/include/wx.hrl").

-export([wxID_ANY/0, wxID_YES/0, wxID_NO/0, wxYES/0, wxNO/0,
         wxYES_NO/0, wxYES_DEFAULT/0, wxNO_DEFAULT/0, wxICON_QUESTION/0]).

wxID_ANY() ->
    ?wxID_ANY.

wxID_YES() ->
    ?wxID_YES.

wxID_NO() ->
    ?wxID_NO.

wxYES() ->
    ?wxYES.

wxNO() ->
    ?wxNO.
wxYES_NO() ->
    ?wxYES_NO.

wxYES_DEFAULT() ->
    ?wxYES_DEFAULT.

wxNO_DEFAULT() ->
    ?wxNO_DEFAULT.

wxICON_QUESTION() ->
    ?wxICON_QUESTION.
