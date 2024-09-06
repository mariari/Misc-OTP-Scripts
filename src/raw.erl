-module(raw).

-behaviour(wx_object).

-export([start/1, init/1, start_link/4]).

-include_lib("wx/include/wx.hrl").

-record(state, {field = 4 :: integer()}).


% Need to replace wx:null() with a meaningful empty parent
start(Object) ->
    wx_object:start_link(?MODULE, {wx:null(), self(), Object, []}, []).

start_link(Notebook, Parent, Object, Config) ->
    wx_object:start_link(?MODULE, {Notebook, Parent, Object, Config}, []).


init(Initial) ->
    wx:batch(fun() -> do_init(Initial) end).


do_init({Notebook, Parent, Object, Config}) ->
    _Page = dummy_page(Notebook, "First Version of Raw"),
    Page = view(Notebook, Object),
    {Page, #state{field = 1}}.

view(Notebook, Object) ->
    Panel = wxPanel:new(Notebook, []),
    Columned = wxTreeCtrl:new(Panel, []),
    RootID = wxTreeCtrl:addRoot(Columned, "Root"),

    lists:map(fun(X) ->
                wxTreeCtrl:appendItem(Columned,
                                      RootID,
                                      lists:flatten(io_lib:format("~p",[X])))
              end,
              tuple_to_list(Object)),

    wxTreeCtrl:expand(Columned, RootID),

    %% Setup sizers
    MainSizer = wxBoxSizer:new(?wxVERTICAL),
    Sizer = wxStaticBoxSizer:new(?wxVERTICAL, Panel,
				 [{label, "wxTreeCtrl"}]),


    Options = [{flag, ?wxEXPAND}, {proportion, 1}],
    wxSizer:add(Sizer, Columned, Options),
    wxSizer:add(MainSizer, Sizer, Options),
    wxPanel:setSizer(Panel, MainSizer),

    Panel.

%% We will use a dummy page and a real page at some page
dummy_page(Notebook, Text) ->
    Win1 = wxPanel:new(Notebook, []),
    Win1Text = wxStaticText:new(Win1, ?wxID_ANY, Text),

    Sizer1 = wxBoxSizer:new(?wxHORIZONTAL),
    wxSizer:add(Sizer1, Win1Text),
    wxPanel:setSizer(Win1, Sizer1),

    wxStaticText:setForegroundColour(Win1Text, ?wxBLACK),
    Win1.
