-module(wx_hello).

-include_lib("wx/include/wx.hrl").

-export([first/0, first_with_style/0, countdown/1, countdown/0]).


first() ->
    wx:new(),
    M = wxMessageDialog:new(wx:null(), "Hello World"),
    wxMessageDialog:showModal(M),
    wxMessageDialog:destroy(M).

first_with_style() ->
    wx:new(),
    Style = ?wxICON_QUESTION bor ?wxYES_NO bor ?wxYES_DEFAULT,
    M = wxMessageDialog:new(wx:null(), "Hello World?", [{style, Style}]),
    wxMessageDialog:showModal(M),
    wxMessageDialog:destroy(M).

countdown() ->
    countdown(3).

countdown(Seconds) ->
    wx:new(),
    Frame = wxFrame:new(wx:null(), ?wxID_ANY, "Countdown"),
    Counter = wxStaticText:new(Frame, ?wxID_ANY, integer_to_list(Seconds)),
    wxFrame:show(Frame),
    countdown_helper(Seconds - 1, Counter),
    wxStaticText:destroy(Counter),
    wxFrame:destroy(Frame).


countdown_helper(Seconds, _) when Seconds < 0 ->
    ok;
countdown_helper(Seconds, Counter) ->
    timer:sleep(1000),
    wxStaticText:setLabel(Counter, integer_to_list(Seconds)),
    countdown_helper(Seconds - 1, Counter).
