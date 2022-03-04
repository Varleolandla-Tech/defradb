<a name="v0.2.1"></a>
## [v0.2.1](https://github.com/sourcenetwork/defradb/compare/v0.2.0...v0.2.1)

> 2022-03-04

### Features

* Add ability to delete multiple documents using filter ([#206](https://github.com/sourcenetwork/defradb/issues/206))
* Add ability to delete multiple documents, using multiple ids ([#196](https://github.com/sourcenetwork/defradb/issues/196))

### Fixes

* Concurrency control of Document using RWMutex ([#213](https://github.com/sourcenetwork/defradb/issues/213))
* Only log errors and above when benchmarking ([#261](https://github.com/sourcenetwork/defradb/issues/261))
* Handle proper type conversion on sort nodes ([#228](https://github.com/sourcenetwork/defradb/issues/228))
* Return empty array if no values found ([#223](https://github.com/sourcenetwork/defradb/issues/223))
* Close fetcher on error ([#210](https://github.com/sourcenetwork/defradb/issues/210))
* Installing binary using defradb name ([#190](https://github.com/sourcenetwork/defradb/issues/190))

### Tooling

* Add short benchmark runner option ([#263](https://github.com/sourcenetwork/defradb/issues/263))

### Documentation

* Add data format changes documentation folder ([#89](https://github.com/sourcenetwork/defradb/issues/89))
* Correcting typos ([#143](https://github.com/sourcenetwork/defradb/issues/143))
* Update generated CLI docs ([#208](https://github.com/sourcenetwork/defradb/issues/208))
* Updated readme with P2P section ([#220](https://github.com/sourcenetwork/defradb/issues/220))
* Update old or missing license headers ([#205](https://github.com/sourcenetwork/defradb/issues/205))
* Update git-chglog config and template ([#195](https://github.com/sourcenetwork/defradb/issues/195))

### Refactoring

* Introduction of logging system ([#67](https://github.com/sourcenetwork/defradb/issues/67))
* Restructure db/txn/multistore structures ([#199](https://github.com/sourcenetwork/defradb/issues/199))
* Initialize database in constructor ([#211](https://github.com/sourcenetwork/defradb/issues/211))
* Purge all println and ban it ([#253](https://github.com/sourcenetwork/defradb/issues/253))

### Testing

* Detect and force breaking filesystem changes to be documented ([#89](https://github.com/sourcenetwork/defradb/issues/89))
* Boost collection test coverage ([#183](https://github.com/sourcenetwork/defradb/issues/183))

### Continuous integration

* Combine the Lint and Benchmark workflows so that the benchmark job depends on the lint job in one workflow ([#209](https://github.com/sourcenetwork/defradb/issues/209))
* Add rule to only run benchmark if other check are successful ([#194](https://github.com/sourcenetwork/defradb/issues/194))
* Increase linter timeout ([#230](https://github.com/sourcenetwork/defradb/issues/230))

### Chore

* Remove commented out code ([#238](https://github.com/sourcenetwork/defradb/issues/238))
* Remove dead code from multi node ([#186](https://github.com/sourcenetwork/defradb/issues/186))


<a name="v0.2.0"></a>
## [v0.2.0](https://github.com/sourcenetwork/defradb/compare/v0.1.0...v0.2.0)

> 2022-02-07

DefraDB v0.2 is a major pre-production release. Until the stable version 1.0 is reached, the SemVer minor patch number will denote notable releases, which will give the project freedom to experiment and explore potentially breaking changes.

This release is jam-packed with new features and a small number of breaking changes. Read the full changelog for a detailed description. Most notable features include a new Peer-to-Peer (P2P) data synchronization system, an expanded query system to support GroupBy & Aggregate operations, and lastly TimeTraveling queries allowing to query previous states of a document.

Much more than just that has been added to ensure we're building reliable software expected of any database, such as expanded test & benchmark suites, automated bug detection, performance gains, and more.

This release does include a Breaking Change to existing v0.1 databases regarding the internal data model, which affects the "Content Identifiers" we use to generate DocKeys and VersionIDs. If you need help migrating an existing deployment, reach out at hello@source.network or join our Discord at https://discord.source.network.

### Features

* Added Peer-to-Peer networking data synchronization ([#177](https://github.com/sourcenetwork/defradb/issues/177))
* TimeTraveling (History Traversing) query engine and doc fetcher ([#59](https://github.com/sourcenetwork/defradb/issues/59))
* Add Document Deletion with a Key ([#150](https://github.com/sourcenetwork/defradb/issues/150))
* Add support for sum aggregate ([#121](https://github.com/sourcenetwork/defradb/issues/121))
* Add support for lwwr scalar arrays (full replace on update) ([#115](https://github.com/sourcenetwork/defradb/issues/115))
* Add count aggregate support ([#102](https://github.com/sourcenetwork/defradb/issues/102))
* Add support for named relationships ([#108](https://github.com/sourcenetwork/defradb/issues/108))
* Add multi doc key lookup support ([#76](https://github.com/sourcenetwork/defradb/issues/76))
* Add basic group by functionality ([#43](https://github.com/sourcenetwork/defradb/issues/43))
* Update datastore packages to allow use of context ([#48](https://github.com/sourcenetwork/defradb/issues/48))

### Bug fixes

* Only add join if aggregating child object collection ([#188](https://github.com/sourcenetwork/defradb/issues/188))
* Handle errors generated during input object thunks ([#123](https://github.com/sourcenetwork/defradb/issues/123))
* Remove new types from in-memory cache on generate error ([#122](https://github.com/sourcenetwork/defradb/issues/122))
* Support relationships where both fields have the same name ([#109](https://github.com/sourcenetwork/defradb/issues/109))
* Handle errors generated in fields thunk ([#66](https://github.com/sourcenetwork/defradb/issues/66))
* Ensure OperationDefinition case has at least one selection([#24](https://github.com/sourcenetwork/defradb/pull/24))
* Close datastore iterator on scan close ([#56](https://github.com/sourcenetwork/defradb/pull/56)) (resulted in a panic when using limit)
* Close superseded iterators before orphaning ([#56](https://github.com/sourcenetwork/defradb/pull/56)) (fixes a panic in the join code) 
* Move discard to after error check ([#88](https://github.com/sourcenetwork/defradb/pull/88)) (did result in panic if transaction creation fails)
* Check for nil iterator before closing document fetcher ([#108](https://github.com/sourcenetwork/defradb/pull/108))

### Tooling
* Added benchmark suite ([#160](https://github.com/sourcenetwork/defradb/issues/160))

### Documentation

* Correcting comment typos ([#142](https://github.com/sourcenetwork/defradb/issues/142))
* Correcting README typos ([#140](https://github.com/sourcenetwork/defradb/issues/140))

### Testing

* Add transaction integration tests ([#175](https://github.com/sourcenetwork/defradb/issues/175))
* Allow running of tests using badger-file as well as IM options ([#128](https://github.com/sourcenetwork/defradb/issues/128))
* Add test datastore selection support ([#88](https://github.com/sourcenetwork/defradb/issues/88))

### Refactoring

* Datatype modification protection ([#138](https://github.com/sourcenetwork/defradb/issues/138))
* Cleanup Linter Complaints and Setup Makefile ([#63](https://github.com/sourcenetwork/defradb/issues/63))
* Rework document rendering to avoid data duplication and mutation ([#68](https://github.com/sourcenetwork/defradb/issues/68))
* Remove dependency on concrete datastore implementations from db package ([#51](https://github.com/sourcenetwork/defradb/issues/51))
* Remove all `errors.Wrap` and update them with `fmt.Errorf`. ([#41](https://github.com/sourcenetwork/defradb/issues/41))
* Restructure integration tests to provide better visibility ([#15](https://github.com/sourcenetwork/defradb/pull/15))
* Remove schemaless code branches ([#23](https://github.com/sourcenetwork/defradb/pull/23))

### Performance
* Add badger multi scan support ([#85](https://github.com/sourcenetwork/defradb/pull/85))
* Add support for range spans ([#86](https://github.com/sourcenetwork/defradb/pull/86))

### Continous integration

* Use more accurate test coverage. ([#134](https://github.com/sourcenetwork/defradb/issues/134))
* Disable Codecov's Patch Check
* Make codcov less strict for now to unblock development ([#125](https://github.com/sourcenetwork/defradb/issues/125))
* Add codecov config file. ([#118](https://github.com/sourcenetwork/defradb/issues/118))
* Add workflow that runs a job on AWS EC2 instance. ([#110](https://github.com/sourcenetwork/defradb/issues/110))
* Add Code Test Coverage with CodeCov ([#116](https://github.com/sourcenetwork/defradb/issues/116))
* Integrate GitHub Action for golangci-lint Annotations ([#106](https://github.com/sourcenetwork/defradb/issues/106))
* Add Linter Check to CircleCi ([#92](https://github.com/sourcenetwork/defradb/issues/92))

### Chore

* Remove the S1038 rule of the gosimple linter. ([#129](https://github.com/sourcenetwork/defradb/issues/129))
* Update to badger v3, and use badger as default in memory store ([#56](https://github.com/sourcenetwork/defradb/issues/56))
* Make Cid versions consistent ([#57](https://github.com/sourcenetwork/defradb/issues/57))


<a name="v0.1.0"></a>
## v0.1.0

> 2021-03-15
